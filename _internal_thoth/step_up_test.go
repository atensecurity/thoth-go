package thoth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

func makeStepUpServer(t *testing.T, allowAfter time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(allowAfter):
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := thoth.EnforcementDecision{Decision: thoth.DecisionAllow}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestStepUpClient_ReturnsAllowWhenApproved(t *testing.T) {
	t.Parallel()
	srv := makeStepUpServer(t, 0)
	defer srv.Close()

	client := thoth.NewStepUpClient(srv.URL, "", 10*time.Millisecond)
	dec := client.Wait(context.Background(), "hold-token-1")

	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("Decision = %q, want ALLOW", dec.Decision)
	}
}

func TestStepUpClient_ReturnsBlockOnContextDeadline(t *testing.T) {
	t.Parallel()
	// Server blocks until request context is canceled.
	srv := makeStepUpServer(t, 30*time.Second)
	defer srv.Close()

	client := thoth.NewStepUpClient(srv.URL, "", 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	dec := client.Wait(ctx, "hold-token-2")

	if dec.Decision != thoth.DecisionBlock {
		t.Errorf("Decision = %q, want BLOCK on timeout", dec.Decision)
	}
	if dec.Reason != "step-up auth timeout" {
		t.Errorf("Reason = %q, want %q", dec.Reason, "step-up auth timeout")
	}
}

func TestStepUpClient_DefaultPollInterval(t *testing.T) {
	t.Parallel()
	client := thoth.NewStepUpClient("http://enforcer:8080", "", 0)
	if client.PollInterval() != 5*time.Second {
		t.Errorf("PollInterval() = %v, want 5s", client.PollInterval())
	}
}

func TestStepUpClient_PollsUntilApproved(t *testing.T) {
	t.Parallel()
	callCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if count < 3 {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionStepUp})
		} else {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(thoth.EnforcementDecision{Decision: thoth.DecisionAllow})
		}
	}))
	defer srv.Close()

	client := thoth.NewStepUpClient(srv.URL, "", 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dec := client.Wait(ctx, "hold-token-3")

	if dec.Decision != thoth.DecisionAllow {
		t.Errorf("Decision = %q, want ALLOW after polling", dec.Decision)
	}
	mu.Lock()
	defer mu.Unlock()
	if callCount < 3 {
		t.Errorf("expected at least 3 poll calls, got %d", callCount)
	}
}

func TestStepUpClient_ParsesHoldTokenResolutionAllow(t *testing.T) {
	t.Parallel()
	callCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		count := callCount
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if count == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":      "hold-token-allow",
				"resolved":   false,
				"resolution": nil,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "hold-token-allow",
			"resolved":   true,
			"resolution": "ALLOW",
		})
	}))
	defer srv.Close()

	client := thoth.NewStepUpClient(srv.URL, "", 10*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dec := client.Wait(ctx, "hold-token-allow")
	if dec.Decision != thoth.DecisionAllow {
		t.Fatalf("Decision = %q, want ALLOW", dec.Decision)
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount < 2 {
		t.Fatalf("expected at least 2 poll calls, got %d", callCount)
	}
}

func TestStepUpClient_ParsesHoldTokenResolutionBlock(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "hold-token-block",
			"resolved":   true,
			"resolution": "BLOCK",
		})
	}))
	defer srv.Close()

	client := thoth.NewStepUpClient(srv.URL, "", 10*time.Millisecond)
	dec := client.Wait(context.Background(), "hold-token-block")
	if dec.Decision != thoth.DecisionBlock {
		t.Fatalf("Decision = %q, want BLOCK", dec.Decision)
	}
}
