package thoth_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

func TestEnforcerClient_TrailingDataAndNullBlockInBothModes(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"trailing data": `{"decision":"ALLOW"} {"decision":"ALLOW"}`,
		"trailing junk": `{"decision":"ALLOW"}xyz`,
		"null":          `null`,
	} {
		for _, failOpen := range []bool{true, false} {
			body, failOpen := body, failOpen
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
				defer srv.Close()
				dec, _ := thoth.NewEnforcerClient(srv.URL, "", failOpen).Check(context.Background(), thoth.CheckRequest{ToolName: "t", SessionID: "s"})
				if dec.Decision != thoth.DecisionBlock || dec.Reason != "enforcer response not understood" {
					t.Fatalf("got %q %q", dec.Decision, dec.Reason)
				}
			})
		}
	}
}

// brokenBody answers 200 headers promising more bytes than it sends, then drops the connection.
func brokenBody(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "200")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"decision":`))
	w.(http.Flusher).Flush()
	panic(http.ErrAbortHandler)
}

func TestEnforcerClient_BodyReadFailureIsATransportError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(brokenBody))
	defer srv.Close()
	req := thoth.CheckRequest{ToolName: "t", SessionID: "s"}
	dec, err := thoth.NewEnforcerClient(srv.URL, "", true).Check(context.Background(), req)
	if err != nil || dec.Decision != thoth.DecisionAllow {
		t.Errorf("fail-open: %q %v, want ALLOW", dec.Decision, err)
	}
	dec, err = thoth.NewEnforcerClient(srv.URL, "", false).Check(context.Background(), req)
	if err == nil || dec.Decision != thoth.DecisionBlock {
		t.Errorf("fail-closed: %q %v, want BLOCK with error", dec.Decision, err)
	}
}

func TestEnforcerClient_ClientErrorReasonAndRequestNotBuiltReason(t *testing.T) {
	t.Parallel()
	srv := makeEnforcerServer(t, thoth.DecisionBlock, "forbidden", http.StatusForbidden)
	defer srv.Close()
	dec, _ := thoth.NewEnforcerClient(srv.URL, "", true).Check(context.Background(), thoth.CheckRequest{ToolName: "t", SessionID: "s"})
	if dec.Decision != thoth.DecisionBlock || dec.Reason != "enforcer rejected request (status=403)" {
		t.Errorf("4xx: %q %q", dec.Decision, dec.Reason)
	}
	for _, failOpen := range []bool{true, false} {
		dec, err := thoth.NewEnforcerClient(srv.URL, "", failOpen).Check(context.Background(),
			thoth.CheckRequest{ToolName: "t", SessionID: "s", ToolArgs: map[string]any{"x": math.NaN()}})
		if err == nil || dec.Decision != thoth.DecisionBlock || dec.Reason != "request could not be built" {
			t.Errorf("marshal failOpen=%v: %q %q %v", failOpen, dec.Decision, dec.Reason, err)
		}
	}
}

func TestUsageRestoredWhenRequestNeverSent(t *testing.T) {
	huge := map[string]any{"x": strings.Repeat("a", thoth.MaxRequestBytes+1)}
	for name, args := range map[string]map[string]any{"marshal error": {"x": math.NaN()}, "over 4 MiB": huge} {
		args := args
		t.Run(name, func(t *testing.T) {
			c, state := newUsageClient(t)
			c.ReportUsage(thoth.Usage{PromptTokens: 120, CompletionTokens: 30})
			_, _ = c.Check(context.Background(), thoth.CheckRequest{ToolName: "read", SessionID: "s", AgentID: "a", TenantID: "t", ToolArgs: args})
			check(t, c)
			state.mu.Lock()
			defer state.mu.Unlock()
			if len(state.bodies) != 1 {
				t.Fatalf("server saw %d requests, want 1", len(state.bodies))
			}
			if p, _ := num(state.bodies[0], "prompt_tokens"); p != 120 {
				t.Fatalf("usage not restored: %v", state.bodies[0])
			}
		})
	}
}

// First reply misbehaves as chosen, later ones are good; the second request's body is recorded.
func usageAfterFirstReply(t *testing.T, first http.HandlerFunc) (promptTokens float64) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		call := n
		mu.Unlock()
		if call == 1 {
			first(w, r)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		promptTokens, _ = num(body, "prompt_tokens")
		_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
	}))
	defer srv.Close()
	c := thoth.NewEnforcerClient(srv.URL, "key", false)
	c.ReportUsage(thoth.Usage{PromptTokens: 120})
	check(t, c)
	check(t, c)
	return promptTokens
}

func TestUsageRestoredOnBodyReadFailure(t *testing.T) {
	if got := usageAfterFirstReply(t, brokenBody); got != 120 {
		t.Fatalf("usage not restored after a body read failure: %v", got)
	}
}

func TestUsageNotRestoredOnUnreadableReplyOrClientError(t *testing.T) {
	garbage := func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>`)) }
	forbidden := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }
	for name, h := range map[string]http.HandlerFunc{"unreadable 2xx": garbage, "4xx": forbidden} {
		if got := usageAfterFirstReply(t, h); got != 0 {
			t.Errorf("%s: usage was resent (%v) though the server processed the call", name, got)
		}
	}
}
