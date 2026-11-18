package thoth_test

import (
	"math"
	"sync"
	"testing"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

func sentTotals(t *testing.T, state *usageServer) (prompt, completion, cost float64) {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, body := range state.bodies {
		p, _ := num(body, "prompt_tokens")
		c, _ := num(body, "completion_tokens")
		d, _ := num(body, "estimated_cost_usd")
		if p+c > float64(thoth.MaxUsageTokens) || d > thoth.MaxUsageCostUSD {
			t.Fatalf("one request exceeds the per-request maximum: %v", body)
		}
		prompt, completion, cost = prompt+p, completion+c, cost+d
	}
	return prompt, completion, cost
}

func TestManyReportsBeyondTheCapAreSplitAcrossRequestsAndNothingIsLost(t *testing.T) {
	c, state := newUsageClient(t)
	cost := 90.0
	for i := 0; i < 25; i++ {
		c.ReportUsage(thoth.Usage{PromptTokens: 4_000_000, CompletionTokens: 3_000_000, CostUSD: &cost})
	}
	for i := 0; i < 40; i++ {
		check(t, c)
	}
	p, co, d := sentTotals(t, state)
	if p != 100_000_000 || co != 75_000_000 || math.Abs(d-2250) > 1e-6 {
		t.Fatalf("lost usage: prompt=%v completion=%v cost=%v", p, co, d)
	}
}

func TestAReportAfterTheCapWasReachedStillCounts(t *testing.T) {
	c, state := newUsageClient(t)
	c.ReportUsage(thoth.Usage{PromptTokens: thoth.MaxUsageTokens})
	c.ReportUsage(thoth.Usage{PromptTokens: 5})
	check(t, c)
	check(t, c)
	if p, _, _ := sentTotals(t, state); p != float64(thoth.MaxUsageTokens)+5 {
		t.Fatalf("prompt = %v", p)
	}
}

func TestConcurrentReportsAndChecksCountEverythingOnce(t *testing.T) {
	c, state := newUsageClient(t)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				c.ReportUsage(thoth.Usage{PromptTokens: 1, CompletionTokens: 2})
				if i%10 == 0 {
					check(t, c)
				}
			}
		}()
	}
	wg.Wait()
	check(t, c) // carries whatever is left
	p, co, _ := sentTotals(t, state)
	if p != 1600 || co != 3200 {
		t.Fatalf("prompt=%v completion=%v", p, co)
	}
}
