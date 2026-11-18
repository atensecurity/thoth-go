package thoth_test

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

type usageServer struct {
	mu     sync.Mutex
	bodies []map[string]any
	status []int
}

func (u *usageServer) handler(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	u.mu.Lock()
	u.bodies = append(u.bodies, body)
	status := 200
	if len(u.status) >= len(u.bodies) {
		status = u.status[len(u.bodies)-1]
	}
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
}

func newUsageClient(t *testing.T, statuses ...int) (*thoth.EnforcerClient, *usageServer) {
	t.Helper()
	state := &usageServer{status: statuses}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	t.Cleanup(server.Close)
	return thoth.NewEnforcerClient(server.URL, "key", false), state
}

func check(t *testing.T, c *thoth.EnforcerClient) {
	t.Helper()
	_, _ = c.Check(context.Background(), thoth.CheckRequest{ToolName: "read", SessionID: "s", AgentID: "a", TenantID: "t"})
}

func num(body map[string]any, key string) (float64, bool) {
	value, ok := body[key].(float64)
	return value, ok
}

func TestUsageRidesOnTheNextCallOnce(t *testing.T) {
	c, state := newUsageClient(t)
	c.ReportUsage(thoth.Usage{PromptTokens: 120, CompletionTokens: 30})
	check(t, c)
	check(t, c)
	if p, _ := num(state.bodies[0], "prompt_tokens"); p != 120 {
		t.Fatalf("prompt_tokens = %v", state.bodies[0])
	}
	if c2, _ := num(state.bodies[0], "completion_tokens"); c2 != 30 {
		t.Fatalf("completion_tokens = %v", state.bodies[0])
	}
	if _, ok := state.bodies[0]["estimated_cost_usd"]; ok {
		t.Fatal("dollars are sent only when the caller set them")
	}
	for _, key := range []string{"prompt_tokens", "completion_tokens", "estimated_cost_usd"} {
		if _, ok := state.bodies[1][key]; ok {
			t.Fatalf("usage was sent twice: %v", state.bodies[1])
		}
	}
}

func TestUsageAddsUpAndCostIsOptional(t *testing.T) {
	c, state := newUsageClient(t)
	cost := 0.25
	c.ReportUsage(thoth.Usage{PromptTokens: 10, CompletionTokens: 5})
	c.ReportUsage(thoth.Usage{PromptTokens: 20, CompletionTokens: 15, CostUSD: &cost})
	check(t, c)
	p, _ := num(state.bodies[0], "prompt_tokens")
	cc, _ := num(state.bodies[0], "completion_tokens")
	d, _ := num(state.bodies[0], "estimated_cost_usd")
	if p != 30 || cc != 20 || d != 0.25 {
		t.Fatalf("got %v", state.bodies[0])
	}
}

func TestInvalidAndZeroUsageIsIgnoredAndHugeIsCapped(t *testing.T) {
	c, state := newUsageClient(t)
	bad := math.NaN()
	inf := math.Inf(1)
	neg := -1.0
	c.ReportUsage(thoth.Usage{PromptTokens: -5, CompletionTokens: 0, CostUSD: &bad})
	c.ReportUsage(thoth.Usage{CostUSD: &inf})
	c.ReportUsage(thoth.Usage{CostUSD: &neg})
	check(t, c)
	for _, key := range []string{"prompt_tokens", "completion_tokens", "estimated_cost_usd"} {
		if _, ok := state.bodies[0][key]; ok {
			t.Fatalf("%s should not be sent: %v", key, state.bodies[0])
		}
	}
	huge := 1e12
	c.ReportUsage(thoth.Usage{PromptTokens: math.MaxInt64, CompletionTokens: math.MaxInt64, CostUSD: &huge})
	c.ReportUsage(thoth.Usage{PromptTokens: math.MaxInt64})
	check(t, c)
	p, _ := num(state.bodies[1], "prompt_tokens")
	d, _ := num(state.bodies[1], "estimated_cost_usd")
	if p != float64(thoth.MaxUsageTokens) || d != thoth.MaxUsageCostUSD {
		t.Fatalf("not capped: %v", state.bodies[1])
	}
}

func TestUsageIsNotLostWhenTheServerDidNotCountTheCall(t *testing.T) {
	c, state := newUsageClient(t, 503, 200)
	c.ReportUsage(thoth.Usage{PromptTokens: 50, CompletionTokens: 50})
	check(t, c)
	check(t, c)
	if p, _ := num(state.bodies[1], "prompt_tokens"); p != 50 {
		t.Fatalf("retry lost usage: %v", state.bodies)
	}
}

func TestAClientErrorDoesNotResendUsage(t *testing.T) {
	c, state := newUsageClient(t, 403, 200)
	c.ReportUsage(thoth.Usage{PromptTokens: 50})
	check(t, c)
	check(t, c)
	if _, ok := state.bodies[1]["prompt_tokens"]; ok {
		t.Fatalf("usage resent after a client error: %v", state.bodies[1])
	}
}
