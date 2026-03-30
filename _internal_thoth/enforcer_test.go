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
	dec, err := client.Check(context.Background(), "read_file", "sess-1", []string{"read_file"})

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
	dec, err := client.Check(context.Background(), "delete_db", "sess-1", []string{"read_file"})

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

func TestEnforcerClient_NetworkErrorFallsBackToAllow(t *testing.T) {
	t.Parallel()
	// Use a closed server to simulate a network error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), "any_tool", "sess-1", nil)

	// Non-fatal: error returned but decision is ALLOW so agent keeps running.
	if err == nil {
		t.Fatal("expected error on network failure")
	}
	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionAllow)
	}
}

func TestEnforcerClient_Non200FallsBackToAllow(t *testing.T) {
	t.Parallel()
	srv := makeEnforcerServer(t, thoth.DecisionBlock, "internal error", http.StatusServiceUnavailable)
	defer srv.Close()

	client := thoth.NewEnforcerClient(srv.URL, "")
	dec, err := client.Check(context.Background(), "tool", "sess-1", nil)

	if err == nil {
		t.Fatal("expected error on non-200 response")
	}
	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionAllow)
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
	dec, err := client.Check(ctx, "tool", "sess-1", nil)

	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("fallback Decision = %q, want %q", dec.Decision, thoth.DecisionAllow)
	}
}

func TestEnforcerClient_Has5sDefaultTimeout(t *testing.T) {
	t.Parallel()
	client := thoth.NewEnforcerClient("http://enforcer:8080", "")
	if client.Timeout() != 5*time.Second {
		t.Errorf("Timeout() = %v, want 5s", client.Timeout())
	}
}
