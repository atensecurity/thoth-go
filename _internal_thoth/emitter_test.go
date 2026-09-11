package thoth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

type mockBatchSender struct {
	mu      sync.Mutex
	batches []*sqs.SendMessageBatchInput
	err     error
}

func sensitiveEvent() *thoth.BehavioralEvent {
	const canary = "SYNTHETIC-PHI-SECRET-4471"
	event := thoth.NewBehavioralEvent(thoth.BehavioralEventInput{
		AgentID: "agent-safe-001", TenantID: "tenant-safe-001", SessionID: "session-safe-001",
		UserID: "user-safe-001", Purpose: canary, DataClassification: canary,
		TaskContext: map[string]any{"patient": canary}, InitiatedBy: canary, TaskID: canary,
		DelegationChain: []string{canary}, SourceType: thoth.SourceAgentToolCall,
		EventType: thoth.EventToolCallBlock, ToolName: "read_document", Content: canary,
		ApprovedScope: []string{"read_document"}, EnforcementMode: thoth.Block,
		Metadata: map[string]any{
			"sdk_language": "go", "environment": "dev", "authorization_decision": "BLOCK",
			"decision_reason_code": "policy_block", "enforcement_trace_id": "trace-safe-001",
			"action_attestation_id": "action-safe-001", "tool_args": map[string]any{"path": canary},
			"error": canary, "human_explanation": map[string]any{"summary": canary},
			"receipt": map[string]any{
				"receipt_id": "receipt-safe-001", "signature": "signature-safe-001",
				"signing_algorithm": "ED25519", "audit_envelope": map[string]any{"patient": canary},
				"decision": map[string]any{"authorization_decision": "BLOCK", "reason": canary, "outcome": "blocked"},
			},
			"decision_evidence": map[string]any{
				"decision_reason_code": "policy_block", "authorization_decision": "BLOCK",
				"risk_score": 91.5,
				"policy":     map[string]any{"matched_rule_ids": []string{"rule-safe-001"}, "explanation": canary},
			},
		},
	})
	event.EventID = "tenant-safe-001:event-safe-001"
	return &event
}

func (m *mockBatchSender) SendMessageBatch(_ context.Context, params *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.batches = append(m.batches, params)
	return &sqs.SendMessageBatchOutput{}, m.err
}

func (m *mockBatchSender) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.batches)
}

func newTestEvent() *thoth.BehavioralEvent {
	ev := thoth.NewBehavioralEvent(thoth.BehavioralEventInput{
		AgentID:         "agent-1",
		TenantID:        "tenant-1",
		SessionID:       "session-1",
		UserID:          "user-1",
		SourceType:      thoth.SourceAgentToolCall,
		EventType:       thoth.EventToolCallPost,
		ToolName:        "tool",
		Content:         "tool invocation completed",
		ApprovedScope:   []string{"tool"},
		EnforcementMode: thoth.Progressive,
		SessionToolCalls: []string{
			"tool",
		},
	})
	return &ev
}

func TestEmit_NoopWhenNoURL(t *testing.T) {
	ctx := context.Background()
	mock := &mockBatchSender{}
	e := thoth.NewSQSEmitter(ctx, "", mock)
	defer e.Close()

	e.Emit(newTestEvent())
	time.Sleep(50 * time.Millisecond)
	if mock.callCount() != 0 {
		t.Fatal("expected no SQS calls for empty URL")
	}
}

func TestEmit_BatchesSentOnClose(t *testing.T) {
	ctx := context.Background()
	mock := &mockBatchSender{}
	e := thoth.NewSQSEmitter(ctx, "https://sqs.us-east-1.amazonaws.com/123/q.fifo", mock)

	for range 5 {
		e.Emit(newTestEvent())
	}
	e.Close()

	if mock.callCount() == 0 {
		t.Fatal("expected at least one SendMessageBatch call")
	}
}

func TestEmit_NonBlocking_WhenFull(t *testing.T) {
	ctx := context.Background()
	mock := &mockBatchSender{err: fmt.Errorf("simulated error")}
	e := thoth.NewSQSEmitter(ctx, "https://sqs.us-east-1.amazonaws.com/123/q.fifo", mock)
	defer e.Close()

	// Fill buffer beyond capacity — must not block or panic.
	done := make(chan struct{})
	go func() {
		for range 1100 {
			e.Emit(newTestEvent())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked when buffer was full")
	}
}

func TestEmit_IsNonBlocking(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mock := &mockBatchSender{}
	e := thoth.NewSQSEmitter(ctx, "https://sqs.us-west-2.amazonaws.com/123/test-queue.fifo", mock)
	defer e.Close()

	start := time.Now()
	e.Emit(newTestEvent())
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("Emit() took %v, expected non-blocking", elapsed)
	}
}

func TestEmit_BatchOf10UsesOneBatchCall(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mock := &mockBatchSender{}
	e := thoth.NewSQSEmitter(ctx, "https://sqs.us-west-2.amazonaws.com/123/test-queue.fifo", mock)

	// Emit exactly 10 events and close. The drain goroutine may pick up some
	// events before all 10 are enqueued (goroutine scheduling), so we allow
	// 1-2 batches. The key invariant: never 10 individual calls.
	for range 10 {
		e.Emit(newTestEvent())
	}
	e.Close()

	if n := mock.callCount(); n < 1 || n > 2 {
		t.Errorf("expected 1-2 SendMessageBatch calls for 10 events, got %d", n)
	}
}

func TestEmit_CloseFlushesRemaining(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	mock := &mockBatchSender{}
	e := thoth.NewSQSEmitter(ctx, "https://sqs.us-west-2.amazonaws.com/123/test-queue.fifo", mock)

	const count = 3
	for range count {
		e.Emit(newTestEvent())
	}
	// Close must block until all enqueued events are flushed.
	e.Close()

	if mock.callCount() == 0 {
		t.Error("expected SendMessageBatch to be called after Close()")
	}
}

func TestHTTPEmitter_SendsDualAuthHeaders(t *testing.T) {
	t.Parallel()

	type requestCapture struct {
		path              string
		authorization     string
		xAPIKey           string
		xEventIngestToken string
		contentType       string
		body              string
	}

	var (
		mu       sync.Mutex
		captures []requestCapture
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		mu.Lock()
		captures = append(captures, requestCapture{
			path:              r.URL.Path,
			authorization:     r.Header.Get("Authorization"),
			xAPIKey:           r.Header.Get("X-Api-Key"),
			xEventIngestToken: r.Header.Get("X-Thoth-Event-Ingest-Token"),
			contentType:       r.Header.Get("Content-Type"),
			body:              string(payload),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	e := thoth.NewHTTPEmitter(server.URL, "aten_test_key")
	e.Emit(newTestEvent())
	e.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(captures) != 1 {
		t.Fatalf("expected exactly one ingest request, got %d", len(captures))
	}
	req := captures[0]
	if req.path != "/v1/events/batch" {
		t.Fatalf("unexpected ingest path: %s", req.path)
	}
	if req.authorization != "Bearer aten_test_key" {
		t.Fatalf("missing/invalid Authorization header: %q", req.authorization)
	}
	if req.xAPIKey != "aten_test_key" {
		t.Fatalf("missing/invalid X-Api-Key header: %q", req.xAPIKey)
	}
	if req.xEventIngestToken != "" {
		t.Fatalf("expected no X-Thoth-Event-Ingest-Token, got: %q", req.xEventIngestToken)
	}
	if req.contentType != "application/json" {
		t.Fatalf("unexpected content-type: %q", req.contentType)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(req.body), &decoded); err != nil {
		t.Fatalf("failed to decode request body: %v", err)
	}
	events, ok := decoded["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("expected single event payload, got: %#v", decoded["events"])
	}
}

func TestHTTPEmitter_UsesMinimalTelemetryProjection(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		body = string(payload)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	event := sensitiveEvent()
	e := thoth.NewHTTPEmitter(server.URL, "test-key")
	e.Emit(event)
	e.Close()

	if strings.Contains(body, "SYNTHETIC-PHI-SECRET-4471") {
		t.Fatalf("serialized telemetry leaked canary: %s", body)
	}
	if !strings.Contains(body, `"event_id":"tenant-safe-001:event-safe-001"`) ||
		!strings.Contains(body, `"receipt_id":"receipt-safe-001"`) ||
		!strings.Contains(body, `"matched_rule_ids":["rule-safe-001"]`) {
		t.Fatalf("serialized telemetry lost decision identifiers/evidence: %s", body)
	}
	if event.TaskContext["patient"] != "SYNTHETIC-PHI-SECRET-4471" {
		t.Fatal("telemetry projection mutated the authorization event")
	}
}

func TestSQSEmitter_UsesMinimalTelemetryProjection(t *testing.T) {
	mock := &mockBatchSender{}
	event := sensitiveEvent()
	e := thoth.NewSQSEmitter(context.Background(), "https://sqs.example/queue.fifo", mock)
	e.Emit(event)
	e.Close()

	if len(mock.batches) != 1 || len(mock.batches[0].Entries) != 1 {
		t.Fatalf("expected one SQS entry, got %#v", mock.batches)
	}
	body := *mock.batches[0].Entries[0].MessageBody
	if strings.Contains(body, "SYNTHETIC-PHI-SECRET-4471") {
		t.Fatalf("serialized telemetry leaked canary: %s", body)
	}
	if !strings.Contains(body, `"action_attestation_id":"action-safe-001"`) {
		t.Fatalf("serialized telemetry lost action identifier: %s", body)
	}
}

func TestHTTPEmitter_SendsEventIngestTokenHeader(t *testing.T) {
	t.Parallel()

	var captured string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		captured = r.Header.Get("X-Thoth-Event-Ingest-Token")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	e := thoth.NewHTTPEmitterWithEventIngestToken(server.URL, "aten_test_key", "ingest-token-123")
	e.Emit(newTestEvent())
	e.Close()

	if captured != "ingest-token-123" {
		t.Fatalf("missing/invalid X-Thoth-Event-Ingest-Token header: %q", captured)
	}
}

func TestHTTPEmitter_Non2xxStillFlushes(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		received int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		received++
		mu.Unlock()
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	e := thoth.NewHTTPEmitter(server.URL, "aten_test_key")
	e.Emit(newTestEvent())
	e.Close()

	mu.Lock()
	defer mu.Unlock()
	if received != 1 {
		t.Fatalf("expected one request despite 403 response, got %d", received)
	}
}
