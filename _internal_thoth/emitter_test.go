package thoth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

type mockBatchSender struct {
	mu      sync.Mutex
	batches []*sqs.SendMessageBatchInput
	err     error
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
		path          string
		authorization string
		xAPIKey       string
		contentType   string
		body          string
	}

	var (
		mu       sync.Mutex
		captures []requestCapture
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		mu.Lock()
		captures = append(captures, requestCapture{
			path:          r.URL.Path,
			authorization: r.Header.Get("Authorization"),
			xAPIKey:       r.Header.Get("X-Api-Key"),
			contentType:   r.Header.Get("Content-Type"),
			body:          string(payload),
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
