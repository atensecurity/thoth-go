package thoth

import (
	"math"
	"sync"
)

// Model usage reported with ReportUsage rides on the next governed call (the
// next /v1/enforce request) as prompt_tokens, completion_tokens and, only when
// the caller passed it, estimated_cost_usd, and is then forgotten: usage is sent
// once. Thoth counts tokens first; it never works dollars out from tokens.
//
// A value that is negative, not finite or not a number is ignored, never an
// error: reporting must not break the agent doing real work. One report is
// capped at 10,000,000 tokens and $1,000 (the server clamps the same way). The running total is
// exact: what one request cannot carry goes with the following governed requests. Usage reported
// after the last governed call has no request to ride on and is not counted.

const (
	// MaxUsageTokens is the most tokens one report can carry.
	MaxUsageTokens int64 = 10_000_000
	// MaxUsageCostUSD is the most dollars one report can carry.
	MaxUsageCostUSD = 1000.0
)

// Usage is the model usage of one or more model calls.
type Usage struct {
	PromptTokens     int64
	CompletionTokens int64
	// CostUSD is optional: set it only when you know the dollar figure.
	CostUSD *float64
}

// pendingUsage keeps exact running totals. Each report is clamped on the way in; the running
// total is never clamped (it saturates only at the int64 range, which 10M-token reports cannot
// reach), so many reports between governed calls are never silently dropped. take hands out at
// most one request's maximum and leaves the rest for the next governed call.
type pendingUsage struct {
	mu         sync.Mutex
	prompt     int64
	completion int64
	cost       float64
	has        bool
}

const saturated = math.MaxInt64 / 2

func addSaturating(a, b int64) int64 {
	if a > saturated-b {
		return saturated
	}
	return a + b
}

func (p *pendingUsage) add(u Usage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if u.PromptTokens > 0 {
		p.prompt = addSaturating(p.prompt, min(u.PromptTokens, MaxUsageTokens))
		p.has = true
	}
	if u.CompletionTokens > 0 {
		p.completion = addSaturating(p.completion, min(u.CompletionTokens, MaxUsageTokens))
		p.has = true
	}
	if u.CostUSD != nil && !math.IsNaN(*u.CostUSD) && !math.IsInf(*u.CostUSD, 0) && *u.CostUSD > 0 {
		p.cost += math.Min(*u.CostUSD, MaxUsageCostUSD)
		p.has = true
	}
}

// take returns up to MaxUsageTokens tokens (prompt and completion together) and MaxUsageCostUSD
// dollars, the server's per-request maximum, and keeps the rest. Nil when nothing is pending.
func (p *pendingUsage) take() *Usage {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.has {
		return nil
	}
	out := &Usage{}
	room := MaxUsageTokens
	out.PromptTokens = min(p.prompt, room)
	room -= out.PromptTokens
	p.prompt -= out.PromptTokens
	out.CompletionTokens = min(p.completion, room)
	p.completion -= out.CompletionTokens
	if p.cost > 0 {
		cost := math.Min(p.cost, MaxUsageCostUSD)
		out.CostUSD = &cost
		p.cost -= cost
		if p.cost < 1e-9 {
			p.cost = 0
		}
	}
	p.has = p.prompt > 0 || p.completion > 0 || p.cost > 0
	return out
}

// ReportUsage records model usage; it is sent with the next governed call.
// Zero and invalid values are ignored.
func (c *EnforcerClient) ReportUsage(u Usage) { c.usage.add(u) }

// ReportUsage records model usage on the tracer's enforcer client.
func (t *Tracer) ReportUsage(u Usage) { t.enforcer.ReportUsage(u) }
