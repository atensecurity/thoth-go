package thoth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

const toolResultOK = "ok"
const testReadInvoicesTool = "read_invoices"
const testUserID = "user_1"

type tracedEnforceRequest struct {
	ToolName         string   `json:"tool_name"`
	SessionToolCalls []string `json:"session_tool_calls"`
}

type captureEmitter struct {
	mu     sync.Mutex
	events []thoth.BehavioralEvent
}

func (c *captureEmitter) Emit(event *thoth.BehavioralEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, *event)
}

func (c *captureEmitter) Close() {}

func (c *captureEmitter) snapshot() []thoth.BehavioralEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]thoth.BehavioralEvent, len(c.events))
	copy(out, c.events)
	return out
}

// --- Test helpers ----------------------------------------------------------

func makeDecisionServer(t *testing.T, decision thoth.DecisionType) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: decision})
	}))
}

func makeTracerConfig(enforcerURL string) thoth.Config {
	return thoth.Config{
		AgentID:       "test-agent",
		TenantID:      "test-tenant",
		ApprovedScope: []string{testReadInvoicesTool, "write_slack"},
		Enforcement:   thoth.Block,
		EnforcerURL:   enforcerURL,
	}
}

// --- WrapTool tests ---------------------------------------------------------

func TestWrapTool_AllowedToolCallsThrough(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionAllow)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	called := false
	fn := func(ctx context.Context, args ...any) (any, error) {
		called = true
		return "result", nil
	}

	wrapped := tracer.WrapTool(testReadInvoicesTool, fn)
	result, err := wrapped(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "result" {
		t.Errorf("result = %v, want %q", result, "result")
	}
	if !called {
		t.Error("underlying function should have been called")
	}
}

func TestWrapTool_BlockedToolReturnsPolicyViolationError(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionBlock)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	called := false
	fn := func(ctx context.Context, args ...any) (any, error) {
		called = true
		return nil, nil
	}

	wrapped := tracer.WrapTool("delete_db", fn)
	_, err := wrapped(context.Background())

	if err == nil {
		t.Fatal("expected error for blocked tool")
	}
	var pve *thoth.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyViolationError, got %T: %v", err, err)
	}
	if pve.ToolName != "delete_db" {
		t.Errorf("ToolName = %q, want delete_db", pve.ToolName)
	}
	if called {
		t.Error("underlying function should NOT have been called when blocked")
	}
}

func TestWrapTool_ObserveMode_NeverBlocks(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionBlock)
	defer srv.Close()

	cfg := thoth.Config{
		AgentID:     "a",
		TenantID:    "t",
		Enforcement: thoth.Observe,
		EnforcerURL: srv.URL,
	}
	cfg = thoth.ApplyConfigDefaults(cfg)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	called := false
	fn := func(ctx context.Context, args ...any) (any, error) {
		called = true
		return toolResultOK, nil
	}

	wrapped := tracer.WrapTool("any_tool", fn)
	_, err := wrapped(context.Background())

	if err != nil {
		t.Fatalf("Observe mode should never block, got: %v", err)
	}
	if !called {
		t.Error("function should be called in Observe mode")
	}
}

func TestWrapTool_RecordsToolCallInSession(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionAllow)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	fn := func(ctx context.Context, args ...any) (any, error) {
		return nil, nil
	}
	wrapped := tracer.WrapTool(testReadInvoicesTool, fn)
	_, _ = wrapped(context.Background())

	calls := sess.ToolCallsCopy()
	if len(calls) != 1 || calls[0] != testReadInvoicesTool {
		t.Errorf("session tool calls = %v, want [%s]", calls, testReadInvoicesTool)
	}
}

func TestWrapTool_EnforcerOutageFailsClosed(t *testing.T) {
	t.Parallel()
	// Use a closed server to simulate outage.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.Enforcement = thoth.Block
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	called := false
	fn := func(ctx context.Context, args ...any) (any, error) {
		called = true
		return toolResultOK, nil
	}
	wrapped := tracer.WrapTool(testReadInvoicesTool, fn)
	_, err := wrapped(context.Background())

	if err == nil {
		t.Fatal("expected block on enforcer outage")
	}
	var pve *thoth.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyViolationError, got %T: %v", err, err)
	}
	if pve.Reason != "enforcer unavailable" {
		t.Errorf("Reason = %q, want %q", pve.Reason, "enforcer unavailable")
	}
	if called {
		t.Error("function should NOT be called on enforcer outage")
	}
}

func TestWrapTool_ProgressiveMode_FirstViolationStepUp_ThenBlock(t *testing.T) {
	t.Parallel()
	// For progressive mode: first call returns step_up, second returns block.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var dec thoth.EnforcementDecision
		if callCount == 1 {
			dec = thoth.EnforcementDecision{Decision: thoth.DecisionStepUp, HoldToken: "tok-1"}
		} else {
			dec = thoth.EnforcementDecision{Decision: thoth.DecisionBlock, Reason: "repeated violation"}
		}
		_ = json.NewEncoder(w).Encode(dec)
	}))
	defer srv.Close()

	cfg := thoth.Config{
		AgentID:     "a",
		TenantID:    "t",
		Enforcement: thoth.Progressive,
		EnforcerURL: srv.URL,
	}
	sess := thoth.NewSessionContext(cfg)
	// Use a very short step-up timeout so the test doesn't hang.
	tracer := thoth.NewTracerWithStepUpTimeout(cfg, sess, nil, 10)

	fn := func(ctx context.Context, args ...any) (any, error) {
		return toolResultOK, nil
	}
	wrapped := tracer.WrapTool("out_of_scope_tool", fn)

	// First call: step-up → times out → returns block.
	_, err := wrapped(context.Background())
	if err == nil {
		t.Fatal("expected error on step-up timeout")
	}
	var pve *thoth.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("expected PolicyViolationError, got %T", err)
	}
}

func TestWrapTool_EnforcePayloadIncludesCurrentToolCall(t *testing.T) {
	t.Parallel()
	var got tracedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
	}))
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	fn := func(ctx context.Context, args ...any) (any, error) {
		return toolResultOK, nil
	}
	wrapped := tracer.WrapTool(testReadInvoicesTool, fn)

	_, err := wrapped(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.ToolName != testReadInvoicesTool {
		t.Fatalf("tool_name = %q, want %q", got.ToolName, testReadInvoicesTool)
	}
	if len(got.SessionToolCalls) != 1 || got.SessionToolCalls[0] != testReadInvoicesTool {
		t.Fatalf("session_tool_calls = %v, want [%s]", got.SessionToolCalls, testReadInvoicesTool)
	}
}

func TestWrapTool_SessionToolCallsBoundedTo128(t *testing.T) {
	t.Parallel()
	var got tracedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
	}))
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	sess := thoth.NewSessionContext(cfg)
	tracer := thoth.NewTracer(cfg, sess, nil)

	for i := 0; i < 140; i++ {
		toolName := fmt.Sprintf("tool_%03d", i)
		wrapped := tracer.WrapTool(toolName, func(ctx context.Context, args ...any) (any, error) {
			return toolResultOK, nil
		})
		if _, err := wrapped(context.Background()); err != nil {
			t.Fatalf("call %d unexpected error: %v", i, err)
		}
	}

	if len(got.SessionToolCalls) != 128 {
		t.Fatalf("session_tool_calls length = %d, want 128", len(got.SessionToolCalls))
	}
	if got.SessionToolCalls[0] != "tool_012" {
		t.Fatalf("first session_tool_calls entry = %q, want %q", got.SessionToolCalls[0], "tool_012")
	}
	if got.SessionToolCalls[len(got.SessionToolCalls)-1] != "tool_139" {
		t.Fatalf("last session_tool_calls entry = %q, want %q", got.SessionToolCalls[len(got.SessionToolCalls)-1], "tool_139")
	}
}

func TestWrapTool_EmitsCanonicalLifecycleEvents_AllowPath(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionAllow)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.UserID = testUserID
	sess := thoth.NewSessionContext(cfg)
	emitter := &captureEmitter{}
	tracer := thoth.NewTracer(cfg, sess, emitter)

	wrapped := tracer.WrapTool(testReadInvoicesTool, func(ctx context.Context, args ...any) (any, error) {
		return "ok", nil
	})
	if _, err := wrapped(context.Background(), map[string]any{"invoice_id": "inv_1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != thoth.EventToolCallPre {
		t.Fatalf("first event type = %s, want %s", events[0].EventType, thoth.EventToolCallPre)
	}
	if events[1].EventType != thoth.EventToolCallPost {
		t.Fatalf("second event type = %s, want %s", events[1].EventType, thoth.EventToolCallPost)
	}
	for _, event := range events {
		if event.EventID == "" || event.TenantID == "" || event.SessionID == "" || event.Content == "" {
			t.Fatalf("event missing required canonical fields: %+v", event)
		}
		if event.SourceType != thoth.SourceAgentToolCall {
			t.Fatalf("unexpected source_type=%s", event.SourceType)
		}
		if event.UserID != testUserID {
			t.Fatalf("unexpected user_id=%q", event.UserID)
		}
		if event.ToolName != testReadInvoicesTool {
			t.Fatalf("unexpected tool_name=%q", event.ToolName)
		}
		if len(event.SessionToolCalls) != 1 || event.SessionToolCalls[0] != testReadInvoicesTool {
			t.Fatalf("unexpected session_tool_calls=%v", event.SessionToolCalls)
		}
		if event.TTL <= event.OccurredAt.Unix() {
			t.Fatalf("ttl (%d) should be greater than occurred_at (%d)", event.TTL, event.OccurredAt.Unix())
		}
	}
}

func TestWrapTool_EmitsPreThenBlock_OnBlockDecision(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionBlock)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.UserID = testUserID
	sess := thoth.NewSessionContext(cfg)
	emitter := &captureEmitter{}
	tracer := thoth.NewTracer(cfg, sess, emitter)

	wrapped := tracer.WrapTool("delete_db", func(ctx context.Context, args ...any) (any, error) {
		return nil, nil
	})
	if _, err := wrapped(context.Background()); err == nil {
		t.Fatal("expected policy violation error")
	}

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != thoth.EventToolCallPre || events[1].EventType != thoth.EventToolCallBlock {
		t.Fatalf("unexpected lifecycle order: %s -> %s", events[0].EventType, events[1].EventType)
	}
}

func TestWrapTool_EmitsPreThenBlock_OnDeferDecision(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{
			Decision:            thoth.DecisionDefer,
			DeferReason:         "pending reviewer",
			DeferTimeoutSeconds: 15,
		})
	}))
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.UserID = testUserID
	sess := thoth.NewSessionContext(cfg)
	emitter := &captureEmitter{}
	tracer := thoth.NewTracer(cfg, sess, emitter)

	wrapped := tracer.WrapTool("wire_money", func(ctx context.Context, args ...any) (any, error) {
		return nil, nil
	})
	if _, err := wrapped(context.Background()); err == nil {
		t.Fatal("expected deferred policy violation")
	}

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != thoth.EventToolCallPre || events[1].EventType != thoth.EventToolCallBlock {
		t.Fatalf("unexpected lifecycle order: %s -> %s", events[0].EventType, events[1].EventType)
	}
	if events[1].Content == "" {
		t.Fatal("block event content must be non-empty")
	}
}

func TestWrapTool_EmitsPreThenBlock_OnStepUpTimeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enforce":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{
				Decision:  thoth.DecisionStepUp,
				HoldToken: "tok-timeout",
			})
		case "/v1/enforce/hold/tok-timeout":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.UserID = testUserID
	sess := thoth.NewSessionContext(cfg)
	emitter := &captureEmitter{}
	tracer := thoth.NewTracerWithStepUpTimeout(cfg, sess, emitter, 10)

	wrapped := tracer.WrapTool("approve_wire", func(ctx context.Context, args ...any) (any, error) {
		return "ok", nil
	})
	if _, err := wrapped(context.Background()); err == nil {
		t.Fatal("expected step-up timeout policy violation")
	}

	events := emitter.snapshot()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != thoth.EventToolCallPre || events[1].EventType != thoth.EventToolCallBlock {
		t.Fatalf("unexpected lifecycle order: %s -> %s", events[0].EventType, events[1].EventType)
	}
}

func TestWrapTool_ExecutionError_EmitsPreWithoutPostOrBlock(t *testing.T) {
	t.Parallel()
	srv := makeDecisionServer(t, thoth.DecisionAllow)
	defer srv.Close()

	cfg := makeTracerConfig(srv.URL)
	cfg.UserID = testUserID
	sess := thoth.NewSessionContext(cfg)
	emitter := &captureEmitter{}
	tracer := thoth.NewTracer(cfg, sess, emitter)

	expectedErr := errors.New("tool failed")
	wrapped := tracer.WrapTool(testReadInvoicesTool, func(ctx context.Context, args ...any) (any, error) {
		return nil, expectedErr
	})
	_, err := wrapped(context.Background(), map[string]any{"invoice_id": "inv_1"})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected wrapped error %v, got %v", expectedErr, err)
	}

	events := emitter.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected only PRE event, got %d events", len(events))
	}
	if events[0].EventType != thoth.EventToolCallPre {
		t.Fatalf("unexpected event type %s, want %s", events[0].EventType, thoth.EventToolCallPre)
	}
}
