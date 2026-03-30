package thoth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

const toolResultOK = "ok"

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
		ApprovedScope: []string{"read_invoices", "write_slack"},
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

	wrapped := tracer.WrapTool("read_invoices", fn)
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
	wrapped := tracer.WrapTool("read_invoices", fn)
	_, _ = wrapped(context.Background())

	calls := sess.ToolCallsCopy()
	if len(calls) != 1 || calls[0] != "read_invoices" {
		t.Errorf("session tool calls = %v, want [read_invoices]", calls)
	}
}

func TestWrapTool_EnforcerOutageFallsBackToAllow(t *testing.T) {
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
	wrapped := tracer.WrapTool("read_invoices", fn)
	_, err := wrapped(context.Background())

	if err != nil {
		t.Fatalf("enforcer outage should fall back to ALLOW, got: %v", err)
	}
	if !called {
		t.Error("function should be called on enforcer outage")
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
