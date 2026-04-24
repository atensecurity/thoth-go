package thoth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/atensecurity/thoth-go"
)

// enforcerResponse mirrors the internal EnforcementDecision shape sent over the wire.
type enforcerResponse struct {
	Decision              string         `json:"decision,omitempty"`
	AuthorizationDecision string         `json:"authorization_decision,omitempty"`
	DecisionReasonCode    string         `json:"decision_reason_code,omitempty"`
	ActionClassification  string         `json:"action_classification,omitempty"`
	Reason                string         `json:"reason,omitempty"`
	ViolationID           string         `json:"violation_id,omitempty"`
	HoldToken             string         `json:"hold_token,omitempty"`
	ModifiedToolArgs      map[string]any `json:"modified_tool_args,omitempty"`
	ModificationReason    string         `json:"modification_reason,omitempty"`
	DeferReason           string         `json:"defer_reason,omitempty"`
	DeferTimeoutSeconds   int            `json:"defer_timeout_seconds,omitempty"`
}

type capturedEnforceRequest struct {
	ToolName           string         `json:"tool_name"`
	SessionID          string         `json:"session_id"`
	UserID             string         `json:"user_id"`
	IdentityBinding    map[string]any `json:"identity_binding"`
	ApprovedScope      []string       `json:"approved_scope"`
	SessionIntent      string         `json:"session_intent"`
	ToolArgs           map[string]any `json:"tool_args"`
	Environment        string         `json:"environment"`
	EnforcementTraceID string         `json:"enforcement_trace_id"`
}

// mockEnforcer returns an httptest.Server that always responds with resp.
func mockEnforcer(t *testing.T, resp enforcerResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("mockEnforcer: encode response: %v", err)
		}
	}))
}

// newTestClient creates a Client pointed at the given mock API URL.
// APIKey is set to "test-key" so the internal enforcer URL is derived from APIURL.
func newTestClient(t *testing.T, apiURL string) *sdk.Client {
	t.Helper()
	client, err := sdk.NewClient(sdk.Config{
		APIURL:   apiURL,
		APIKey:   "test-key",
		TenantID: "test-tenant",
		AgentID:  "test-agent",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

// TestNewClientFromEnv verifies that Config fields are populated from environment
// variables when not explicitly provided.
func TestNewClientFromEnv(t *testing.T) {
	t.Setenv("THOTH_API_KEY", "env-api-key")
	t.Setenv("THOTH_TENANT_ID", "env-tenant")
	t.Setenv("THOTH_AGENT_ID", "env-agent")
	t.Setenv("THOTH_API_URL", "https://enforce.env.atensecurity.com")

	client, err := sdk.NewClient(sdk.Config{})
	if err != nil {
		t.Fatalf("NewClient from env: %v", err)
	}
	client.Close()
}

// TestNewClientFromEnv_EmptyEnv verifies NewClient fails when APIURL is missing.
func TestNewClientFromEnv_EmptyEnv(t *testing.T) {
	// Unset all Thoth env vars to ensure a clean state.
	for _, key := range []string{
		"THOTH_API_KEY", "THOTH_TENANT_ID", "THOTH_AGENT_ID", "THOTH_API_URL",
	} {
		t.Setenv(key, "") // t.Setenv restores on cleanup
		os.Unsetenv(key)
	}

	client, err := sdk.NewClient(sdk.Config{})
	if err == nil {
		client.Close()
		t.Fatal("NewClient with empty config: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "APIURL is required") {
		t.Fatalf("NewClient with empty config: unexpected error: %v", err)
	}
}

// TestWrapToolAllow verifies that when the enforcer returns ALLOW, the wrapped
// tool executes normally and returns the tool's result.
func TestWrapToolAllow(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{Decision: "ALLOW"})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	called := false
	greet := client.WrapTool("greet", func(_ context.Context, name string) (string, error) {
		called = true
		return "hello " + name, nil
	})

	result, err := greet(context.Background(), "world")
	if err != nil {
		t.Fatalf("WrapTool(allow): unexpected error: %v", err)
	}
	if result != "hello world" {
		t.Errorf("WrapTool(allow): got %q, want %q", result, "hello world")
	}
	if !called {
		t.Error("WrapTool(allow): underlying tool was not called")
	}
}

// TestWrapToolBlock verifies that when the enforcer returns BLOCK, the wrapped
// tool is not executed and a *PolicyViolationError is returned.
func TestWrapToolBlock(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		Decision:             "BLOCK",
		DecisionReasonCode:   "policy_scope_violation",
		ActionClassification: "write",
		Reason:               "unauthorized data exfiltration",
		ViolationID:          "v-001",
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	called := false
	exfil := client.WrapTool("exfil_data", func(_ context.Context, _ string) (string, error) {
		called = true
		return "secret", nil
	})

	_, err := exfil(context.Background(), "payload")
	if err == nil {
		t.Fatal("WrapTool(block): expected error, got nil")
	}

	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("WrapTool(block): expected *PolicyViolationError, got %T: %v", err, err)
	}
	if pve.ToolName != "exfil_data" {
		t.Errorf("PolicyViolationError.ToolName: got %q, want %q", pve.ToolName, "exfil_data")
	}
	if pve.Reason != "unauthorized data exfiltration" {
		t.Errorf("PolicyViolationError.Reason: got %q, want %q", pve.Reason, "unauthorized data exfiltration")
	}
	if pve.ViolationID != "v-001" {
		t.Errorf("PolicyViolationError.ViolationID: got %q, want %q", pve.ViolationID, "v-001")
	}
	if pve.DecisionReasonCode != "policy_scope_violation" {
		t.Errorf("PolicyViolationError.DecisionReasonCode: got %q, want %q", pve.DecisionReasonCode, "policy_scope_violation")
	}
	if pve.ActionClassification != "write" {
		t.Errorf("PolicyViolationError.ActionClassification: got %q, want %q", pve.ActionClassification, "write")
	}
	if called {
		t.Error("WrapTool(block): underlying tool must not be called on BLOCK")
	}
}

// TestWrapToolStepUp verifies that when the enforcer returns STEP_UP and the
// step-up approval times out, a *PolicyViolationError is returned (not
// StepUpRequiredError — the internal tracer handles the wait and converts
// timeout to block).
//
// We use a step-up mock that always responds 202 Accepted (pending) to force timeout.
func TestWrapToolStepUp(t *testing.T) {
	// The step-up endpoint always returns 202 to simulate pending approval.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/enforce":
			// Return STEP_UP on the enforce check.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(enforcerResponse{
				Decision:  "STEP_UP",
				HoldToken: "tok-abc",
				Reason:    "high-risk tool call",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/enforce/hold/"):
			// Simulate pending approval — never resolves.
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Use a very short timeout so the test completes quickly.
	client, err := sdk.NewClient(sdk.Config{
		APIURL:   srv.URL,
		APIKey:   "test-key",
		TenantID: "test-tenant",
		AgentID:  "test-agent",
		Timeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	called := false
	risky := client.WrapTool("risky_op", func(_ context.Context, _ string) (string, error) {
		called = true
		return "done", nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = risky(ctx, "input")
	if err == nil {
		t.Fatal("WrapTool(step_up timeout): expected error, got nil")
	}

	// After timeout the internal tracer returns a PolicyViolationError.
	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("WrapTool(step_up timeout): expected *PolicyViolationError, got %T: %v", err, err)
	}
	if called {
		t.Error("WrapTool(step_up timeout): underlying tool must not execute on step-up timeout")
	}
}

func TestWrapToolStepUpPendingReturnsStepUpRequiredError(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		Decision: "BLOCK",
		Reason:   "step-up auth required: reviewer approval pending (hold_token=tok-pending-123)",
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	called := false
	risky := client.WrapTool("wire_transfer", func(_ context.Context, _ string) (string, error) {
		called = true
		return "ok", nil
	})

	_, err := risky(context.Background(), "input")
	if err == nil {
		t.Fatal("WrapTool(step_up pending): expected error, got nil")
	}

	var sue *sdk.StepUpRequiredError
	if !errors.As(err, &sue) {
		t.Fatalf("WrapTool(step_up pending): expected *StepUpRequiredError, got %T: %v", err, err)
	}
	if sue.ToolName != "wire_transfer" {
		t.Fatalf("StepUpRequiredError.ToolName: got %q, want %q", sue.ToolName, "wire_transfer")
	}
	if sue.HoldToken != "tok-pending-123" {
		t.Fatalf("StepUpRequiredError.HoldToken: got %q, want %q", sue.HoldToken, "tok-pending-123")
	}
	if !strings.Contains(strings.ToLower(sue.Reason), "pending") {
		t.Fatalf("StepUpRequiredError.Reason: got %q, expected pending reason", sue.Reason)
	}
	if called {
		t.Fatal("WrapTool(step_up pending): underlying tool must not execute")
	}
}

func TestWrapToolStepUpDeniedRemainsPolicyViolation(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		Decision: "BLOCK",
		Reason:   "step-up auth required: step-up denied by reviewer (hold_token=tok-denied-456)",
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	risky := client.WrapTool("wire_transfer", func(_ context.Context, _ string) (string, error) {
		return "ok", nil
	})

	_, err := risky(context.Background(), "input")
	if err == nil {
		t.Fatal("WrapTool(step_up denied): expected error, got nil")
	}

	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("WrapTool(step_up denied): expected *PolicyViolationError, got %T: %v", err, err)
	}
	var sue *sdk.StepUpRequiredError
	if errors.As(err, &sue) {
		t.Fatalf("WrapTool(step_up denied): expected non-step-up terminal block, got *StepUpRequiredError: %+v", sue)
	}
}

func TestWrapToolModify_StringInput(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		Decision:         "MODIFY",
		ModifiedToolArgs: map[string]any{"input": "sanitized"},
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	echo := client.WrapTool("echo", func(_ context.Context, input string) (string, error) {
		return input, nil
	})

	out, err := echo(context.Background(), "original")
	if err != nil {
		t.Fatalf("WrapTool(modify string): unexpected error: %v", err)
	}
	if out != "sanitized" {
		t.Fatalf("WrapTool(modify string): got %q, want %q", out, "sanitized")
	}
}

func TestWrapToolFuncModify_MapArgs(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		AuthorizationDecision: "MODIFY",
		ModifiedToolArgs: map[string]any{
			"a": float64(8),
			"b": float64(2),
		},
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	divide := client.WrapToolFunc("divide", func(_ context.Context, args map[string]any) (any, error) {
		a, _ := args["a"].(float64)
		b, _ := args["b"].(float64)
		return a / b, nil
	})

	result, err := divide(context.Background(), map[string]any{"a": 10.0, "b": 5.0})
	if err != nil {
		t.Fatalf("WrapToolFunc(modify): unexpected error: %v", err)
	}
	if result != 4.0 {
		t.Fatalf("WrapToolFunc(modify): got %v, want 4.0", result)
	}
}

func TestWrapToolDefer(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{
		Decision:            "DEFER",
		DeferReason:         "pending human review",
		DeferTimeoutSeconds: 45,
	})
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	called := false
	tool := client.WrapTool("wire", func(_ context.Context, input string) (string, error) {
		called = true
		return input, nil
	})

	_, err := tool(context.Background(), "send")
	if err == nil {
		t.Fatal("WrapTool(defer): expected error, got nil")
	}
	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("WrapTool(defer): expected *PolicyViolationError, got %T: %v", err, err)
	}
	if !strings.Contains(pve.Reason, "pending human review") {
		t.Fatalf("WrapTool(defer): reason = %q, expected defer reason", pve.Reason)
	}
	if !strings.Contains(pve.Reason, "45s") {
		t.Fatalf("WrapTool(defer): reason = %q, expected retry timeout", pve.Reason)
	}
	if called {
		t.Fatal("WrapTool(defer): underlying tool must not execute")
	}
}

// TestWrapToolEnforcerDown verifies fail-closed behavior: when the enforcer is
// unreachable the tool does not execute and a policy violation is returned.
func TestWrapToolEnforcerDown(t *testing.T) {
	// Point at a URL with nothing listening.
	client, err := sdk.NewClient(sdk.Config{
		APIURL:   "http://127.0.0.1:19999", // nothing listening here
		APIKey:   "test-key",
		TenantID: "test-tenant",
		AgentID:  "test-agent",
		Timeout:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	called := false
	resilient := client.WrapTool("resilient_tool", func(_ context.Context, input string) (string, error) {
		called = true
		return "ok:" + input, nil
	})

	_, err = resilient(context.Background(), "ping")
	if err == nil {
		t.Fatal("WrapTool(enforcer down): expected error, got nil")
	}
	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Fatalf("WrapTool(enforcer down): expected *PolicyViolationError, got %T: %v", err, err)
	}
	if pve.Reason != "enforcer unavailable" {
		t.Errorf("WrapTool(enforcer down): reason = %q, want %q", pve.Reason, "enforcer unavailable")
	}
	if called {
		t.Error("WrapTool(enforcer down): tool must not execute in fail-closed mode")
	}
}

// TestWrapToolUsesUnifiedAPIURL verifies that enforcement calls are sent to APIURL.
func TestWrapToolUsesUnifiedAPIURL(t *testing.T) {
	var enforceHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/enforce" {
			atomic.AddInt32(&enforceHits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client, err := sdk.NewClient(sdk.Config{
		APIURL:   srv.URL,
		APIKey:   "test-key",
		TenantID: "test-tenant",
		AgentID:  "test-agent",
		Timeout:  300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	called := false
	tool := client.WrapTool("read:data", func(_ context.Context, input string) (string, error) {
		called = true
		return "ok:" + input, nil
	})

	result, err := tool(context.Background(), "ping")
	if err != nil {
		t.Fatalf("WrapTool(unified api url): unexpected error: %v", err)
	}
	if !called {
		t.Fatal("WrapTool(unified api url): tool did not execute")
	}
	if result != "ok:ping" {
		t.Fatalf("WrapTool(unified api url): got %q, want %q", result, "ok:ping")
	}
	if atomic.LoadInt32(&enforceHits) == 0 {
		t.Fatal("WrapTool(unified api url): expected /v1/enforce to be called on APIURL")
	}
}

// TestWrapToolFunc verifies the map-based variant delegates correctly.
func TestWrapToolFunc(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{Decision: "ALLOW"})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	multiply := client.WrapToolFunc("multiply", func(_ context.Context, args map[string]any) (any, error) {
		a, _ := args["a"].(float64)
		b, _ := args["b"].(float64)
		return a * b, nil
	})

	result, err := multiply(context.Background(), map[string]any{"a": 3.0, "b": 4.0})
	if err != nil {
		t.Fatalf("WrapToolFunc: unexpected error: %v", err)
	}
	if result != 12.0 {
		t.Errorf("WrapToolFunc: got %v, want 12.0", result)
	}
}

func TestWrapToolFunc_SendsToolArgsToEnforcer(t *testing.T) {
	var got capturedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enforce" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	called := false
	multiply := client.WrapToolFunc("multiply", func(_ context.Context, args map[string]any) (any, error) {
		called = true
		a, _ := args["a"].(float64)
		b, _ := args["b"].(float64)
		return a * b, nil
	})

	result, err := multiply(context.Background(), map[string]any{"a": 3.0, "b": 4.0})
	if err != nil {
		t.Fatalf("WrapToolFunc_SendsToolArgsToEnforcer: unexpected error: %v", err)
	}
	if !called {
		t.Fatal("WrapToolFunc_SendsToolArgsToEnforcer: wrapped tool was not called")
	}
	if result != 12.0 {
		t.Fatalf("WrapToolFunc_SendsToolArgsToEnforcer: got %v, want 12.0", result)
	}
	if got.ToolName != "multiply" {
		t.Fatalf("tool_name = %q, want %q", got.ToolName, "multiply")
	}
	if got.ToolArgs["a"] != float64(3.0) {
		t.Fatalf("tool_args.a = %v, want %v", got.ToolArgs["a"], float64(3.0))
	}
	if got.ToolArgs["b"] != float64(4.0) {
		t.Fatalf("tool_args.b = %v, want %v", got.ToolArgs["b"], float64(4.0))
	}
}

func TestWrapTool_DefaultsEnvironmentAndTraceID(t *testing.T) {
	var got capturedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enforce" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)
	tool := client.WrapTool("echo", func(_ context.Context, input string) (string, error) {
		return input, nil
	})

	out, err := tool(context.Background(), "hello")
	if err != nil {
		t.Fatalf("WrapTool(default env/trace): unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("WrapTool(default env/trace): got %q, want %q", out, "hello")
	}
	if got.Environment != "prod" {
		t.Fatalf("environment = %q, want %q", got.Environment, "prod")
	}
	if got.SessionID == "" {
		t.Fatal("session_id should not be empty")
	}
	if got.EnforcementTraceID != got.SessionID {
		t.Fatalf("enforcement_trace_id = %q, want session_id %q", got.EnforcementTraceID, got.SessionID)
	}
}

func TestWrapTool_UsesConfiguredEnvironmentAndTraceID(t *testing.T) {
	var got capturedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enforce" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client, err := sdk.NewClient(sdk.Config{
		APIURL:             srv.URL,
		APIKey:             "test-key",
		TenantID:           "test-tenant",
		AgentID:            "test-agent",
		Timeout:            2 * time.Second,
		Environment:        "dev",
		EnforcementTraceID: "trace-explicit",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	tool := client.WrapTool("echo", func(_ context.Context, input string) (string, error) {
		return input, nil
	})

	out, err := tool(context.Background(), "hello")
	if err != nil {
		t.Fatalf("WrapTool(explicit env/trace): unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("WrapTool(explicit env/trace): got %q, want %q", out, "hello")
	}
	if got.Environment != "dev" {
		t.Fatalf("environment = %q, want %q", got.Environment, "dev")
	}
	if got.EnforcementTraceID != "trace-explicit" {
		t.Fatalf("enforcement_trace_id = %q, want %q", got.EnforcementTraceID, "trace-explicit")
	}
}

func TestWrapTool_PropagatesUserScopeAndSessionIntent(t *testing.T) {
	var got capturedEnforceRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enforce" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client, err := sdk.NewClient(sdk.Config{
		APIURL:        srv.URL,
		APIKey:        "test-key",
		TenantID:      "test-tenant",
		AgentID:       "test-agent",
		UserID:        "user-456",
		ApprovedScope: []string{"read_file", "search_docs"},
		SessionIntent: "triage",
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	tool := client.WrapTool("read_file", func(_ context.Context, input string) (string, error) {
		return input, nil
	})
	out, err := tool(context.Background(), "hello")
	if err != nil {
		t.Fatalf("WrapTool(user/scope/intent): unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("WrapTool(user/scope/intent): got %q, want %q", out, "hello")
	}
	if got.UserID != "user-456" {
		t.Fatalf("user_id = %q, want %q", got.UserID, "user-456")
	}
	if len(got.ApprovedScope) != 2 || got.ApprovedScope[0] != "read_file" || got.ApprovedScope[1] != "search_docs" {
		t.Fatalf("approved_scope = %v, want [read_file search_docs]", got.ApprovedScope)
	}
	if got.SessionIntent != "triage" {
		t.Fatalf("session_intent = %q, want %q", got.SessionIntent, "triage")
	}
	if got.IdentityBinding["agent_id"] != "test-agent" {
		t.Fatalf("identity_binding.agent_id = %v, want %q", got.IdentityBinding["agent_id"], "test-agent")
	}
	if got.IdentityBinding["tenant_id"] != "test-tenant" {
		t.Fatalf("identity_binding.tenant_id = %v, want %q", got.IdentityBinding["tenant_id"], "test-tenant")
	}
	if got.IdentityBinding["user_id"] != "user-456" {
		t.Fatalf("identity_binding.user_id = %v, want %q", got.IdentityBinding["user_id"], "user-456")
	}
}

// TestStartSession verifies that a session can be created and closed without error.
func TestStartSession(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{Decision: "ALLOW"})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	sess, err := client.StartSession(context.Background(), "my-agent", "")
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if sess.ID == "" {
		t.Error("StartSession: session ID must not be empty")
	}

	// Wrap a tool via session and call it.
	echo := sess.WrapTool("echo", func(_ context.Context, s string) (string, error) {
		return s, nil
	})
	out, err := echo(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Session.WrapTool: %v", err)
	}
	if out != "hello" {
		t.Errorf("Session.WrapTool echo: got %q, want %q", out, "hello")
	}

	sess.Close()
	// Double-close must be safe.
	sess.Close()
}

// TestStartSessionWithExplicitID verifies that a caller-supplied session ID is honored.
func TestStartSessionWithExplicitID(t *testing.T) {
	srv := mockEnforcer(t, enforcerResponse{Decision: "ALLOW"})
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	const wantID = "my-custom-session-id"
	sess, err := client.StartSession(context.Background(), "agent", wantID)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	defer sess.Close()

	if sess.ID != wantID {
		t.Errorf("Session.ID: got %q, want %q", sess.ID, wantID)
	}
}

// TestPolicyViolationErrorInterface verifies the error type satisfies the
// standard error interface and formats legibly.
func TestPolicyViolationErrorInterface(t *testing.T) {
	err := &sdk.PolicyViolationError{
		ToolName:    "delete_all",
		Reason:      "destructive operation not permitted",
		ViolationID: "v-999",
	}

	var _ error = err // compile-time check

	msg := err.Error()
	for _, want := range []string{"delete_all", "destructive operation not permitted", "v-999"} {
		if !contains(msg, want) {
			t.Errorf("PolicyViolationError.Error() missing %q in %q", want, msg)
		}
	}
}

// TestStepUpRequiredErrorInterface verifies StepUpRequiredError satisfies the
// error interface.
func TestStepUpRequiredErrorInterface(t *testing.T) {
	err := &sdk.StepUpRequiredError{
		ToolName:  "wire_transfer",
		HoldToken: "tok-xyz",
		Reason:    "high-value transaction",
	}

	var _ error = err // compile-time check

	msg := err.Error()
	for _, want := range []string{"wire_transfer", "tok-xyz", "high-value transaction"} {
		if !contains(msg, want) {
			t.Errorf("StepUpRequiredError.Error() missing %q in %q", want, msg)
		}
	}
}

// contains is a simple substring check helper.
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
