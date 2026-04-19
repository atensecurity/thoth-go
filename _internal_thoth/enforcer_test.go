package thoth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

type captureEnforceRequest struct {
	ToolName         string         `json:"tool_name"`
	SessionID        string         `json:"session_id"`
	UserID           string         `json:"user_id"`
	ApprovedScope    []string       `json:"approved_scope"`
	SessionToolCalls []string       `json:"session_tool_calls"`
	ToolArgs         map[string]any `json:"tool_args"`
	SessionIntent    string         `json:"session_intent"`
	Environment      string         `json:"environment"`
	TraceID          string         `json:"enforcement_trace_id"`
}

func makeEnforcerServer(t *testing.T, decision thoth.DecisionType, reason string, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		resp := thoth.EnforcementDecision{
			Decision: decision,
			Reason:   reason,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestEnforcerClient_CheckReturnsAllow(t *testing.T) {
	t.Parallel()
	srv := makeEnforcerServer(t, thoth.DecisionAllow, "", http.StatusOK)
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), thoth.CheckRequest{
		ToolName: "read_file", SessionID: "sess-1", SessionToolCalls: []string{"read_file"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("Decision = %q, want %q", dec.Decision, thoth.DecisionAllow)
	}
}

func TestEnforcerClient_CheckReturnsBlock(t *testing.T) {
	t.Parallel()
	srv := makeEnforcerServer(t, thoth.DecisionBlock, "out of scope", http.StatusOK)
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), thoth.CheckRequest{
		ToolName: "delete_db", SessionID: "sess-1", SessionToolCalls: []string{"read_file"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Decision != thoth.DecisionBlock {
		t.Errorf("Decision = %q, want %q", dec.Decision, thoth.DecisionBlock)
	}
	if dec.Reason != "out of scope" {
		t.Errorf("Reason = %q", dec.Reason)
	}
}

func TestEnforcerClient_NetworkErrorFallsBackToBlock(t *testing.T) {
	t.Parallel()
	// Use a closed server to simulate a network error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), thoth.CheckRequest{ToolName: "any_tool", SessionID: "sess-1"})

	if err == nil {
		t.Fatal("expected error on network failure")
	}
	if dec.Decision != thoth.DecisionBlock {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionBlock)
	}
}

func TestEnforcerClient_Non200FallsBackToBlock(t *testing.T) {
	t.Parallel()
	srv := makeEnforcerServer(t, thoth.DecisionBlock, "internal error", http.StatusServiceUnavailable)
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), thoth.CheckRequest{ToolName: "tool", SessionID: "sess-1"})

	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
	if dec.Decision != thoth.DecisionBlock {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionBlock)
	}
}

func TestEnforcerClient_RespectsContextCancellation(t *testing.T) {
	t.Parallel()
	// Slow server to trigger context cancellation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(ctx, thoth.CheckRequest{ToolName: "tool", SessionID: "sess-1"})

	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if dec.Decision != thoth.DecisionBlock {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionBlock)
	}
}

func TestEnforcerClient_Has5sDefaultTimeout(t *testing.T) {
	t.Parallel()
	client := thoth.NewEnforcerClient("http://enforcer:8080", "")
	if client.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", client.Timeout())
	}
}

func TestEnforcerClient_IncludesToolArgsInPayload(t *testing.T) {
	t.Parallel()
	var got captureEnforceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
	}))
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	_, err := client.Check(context.Background(), thoth.CheckRequest{
		ToolName:         "read_file",
		SessionID:        "sess-args",
		SessionToolCalls: []string{"list_files"},
		ToolArgs: map[string]any{
			"path":            "/tmp/a.txt",
			"include_hidden":  true,
			"max_bytes_float": 256.0,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.ToolName != "read_file" {
		t.Fatalf("tool_name = %q, want %q", got.ToolName, "read_file")
	}
	if got.SessionID != "sess-args" {
		t.Fatalf("session_id = %q, want %q", got.SessionID, "sess-args")
	}
	if len(got.SessionToolCalls) != 1 || got.SessionToolCalls[0] != "list_files" {
		t.Fatalf("session_tool_calls = %v, want [list_files]", got.SessionToolCalls)
	}
	if got.ToolArgs["path"] != "/tmp/a.txt" {
		t.Fatalf("tool_args.path = %v, want %q", got.ToolArgs["path"], "/tmp/a.txt")
	}
	if got.ToolArgs["include_hidden"] != true {
		t.Fatalf("tool_args.include_hidden = %v, want true", got.ToolArgs["include_hidden"])
	}
	if got.ToolArgs["max_bytes_float"] != float64(256.0) {
		t.Fatalf("tool_args.max_bytes_float = %v, want %v", got.ToolArgs["max_bytes_float"], float64(256.0))
	}
}

func TestEnforcerClient_IncludesEnvironmentAndTraceID(t *testing.T) {
	t.Parallel()
	var got captureEnforceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
	}))
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	_, err := client.Check(context.Background(), thoth.CheckRequest{
		ToolName:            "read_file",
		SessionID:           "sess-env",
		Environment:         "dev",
		EnforcementTraceID:  "trace-123",
		SessionToolCalls:    []string{"list_files"},
		EnforcementMode:     thoth.Block,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.Environment != "dev" {
		t.Fatalf("environment = %q, want %q", got.Environment, "dev")
	}
	if got.TraceID != "trace-123" {
		t.Fatalf("enforcement_trace_id = %q, want %q", got.TraceID, "trace-123")
	}
}

func TestEnforcerClient_PropagatesUserScopeAndSessionIntent(t *testing.T) {
	t.Parallel()
	var got captureEnforceRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
	}))
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	_, err := client.Check(context.Background(), thoth.CheckRequest{
		ToolName:         "read_file",
		SessionID:        "sess-user",
		UserID:           "user-123",
		ApprovedScope:    []string{"read_file", "search_docs"},
		SessionToolCalls: []string{"search_docs"},
		SessionIntent:    "investigation",
		EnforcementMode:  thoth.Block,
		Environment:      "prod",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.UserID != "user-123" {
		t.Fatalf("user_id = %q, want %q", got.UserID, "user-123")
	}
	if len(got.ApprovedScope) != 2 || got.ApprovedScope[0] != "read_file" || got.ApprovedScope[1] != "search_docs" {
		t.Fatalf("approved_scope = %v, want [read_file search_docs]", got.ApprovedScope)
	}
	if got.SessionIntent != "investigation" {
		t.Fatalf("session_intent = %q, want %q", got.SessionIntent, "investigation")
	}
}
