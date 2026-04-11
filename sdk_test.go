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
	Decision    string `json:"decision"`
	Reason      string `json:"reason,omitempty"`
	ViolationID string `json:"violation_id,omitempty"`
	HoldToken   string `json:"hold_token,omitempty"`
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
	t.Setenv("THOTH_API_URL", "https://enforce.env.aten.security")

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
		Decision:    "BLOCK",
		Reason:      "unauthorized data exfiltration",
		ViolationID: "v-001",
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

// TestWrapToolEnforcerDown verifies fail-open behavior: when the enforcer is
// unreachable the tool executes normally and no error is returned to the caller.
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

	result, err := resilient(context.Background(), "ping")
	if err != nil {
		t.Fatalf("WrapTool(enforcer down): expected nil error (fail-open), got: %v", err)
	}
	if !called {
		t.Error("WrapTool(enforcer down): tool was not called (expected fail-open)")
	}
	if result != "ok:ping" {
		t.Errorf("WrapTool(enforcer down): got %q, want %q", result, "ok:ping")
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
