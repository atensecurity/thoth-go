package thoth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"

	ithoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

// ToolFunc is the generic map-based tool signature used for LLM tool-calling
// frameworks that pass arguments as a key/value map (e.g. OpenAI function calling,
// Anthropic tool use).
type ToolFunc func(ctx context.Context, args map[string]any) (any, error)

// WrapTool wraps a string-in / string-out tool function with Thoth governance.
// This is the most common variant for LLM tool calling, where both the input
// and output are plain strings.
//
// Before each invocation the enforcer is consulted:
//   - ALLOW:   the tool executes normally; a behavioral event is emitted.
//   - BLOCK:   execution is prevented; a *PolicyViolationError is returned.
//   - STEP_UP: execution is paused; the enforcer waits for human approval.
//     On timeout or denial a *PolicyViolationError is returned.
//   - MODIFY:  execution proceeds with policy-modified tool arguments.
//   - DEFER:   execution is deferred; a *PolicyViolationError is returned.
//
// Fail-closed: if the enforcer is unreachable, the tool call is blocked and
// a *PolicyViolationError is returned.
//
// Example:
//
//	searchDocs := client.WrapTool("search_docs", func(ctx context.Context, query string) (string, error) {
//	    return mySearch(ctx, query)
//	})
func (c *Client) WrapTool(
	name string,
	fn func(ctx context.Context, input string) (string, error),
) func(ctx context.Context, input string) (string, error) {
	// Adapt the string-in/string-out signature to internal ToolFunc (variadic any).
	internalFn := ithoth.ToolFunc(func(ctx context.Context, args ...any) (any, error) {
		var input string
		if len(args) > 0 {
			if s, ok := args[0].(string); ok {
				input = s
			}
		}
		return fn(ctx, input)
	})

	wrapped := c.tracer.WrapTool(name, internalFn)

	return func(ctx context.Context, input string) (string, error) {
		result, err := wrapped(ctx, input)
		if err != nil {
			// Translate internal error types to the public SDK error types.
			return "", translateError(err)
		}
		if result == nil {
			return "", nil
		}
		s, ok := result.(string)
		if !ok {
			return fmt.Sprintf("%v", result), nil
		}
		return s, nil
	}
}

// WrapToolFunc wraps a map-based tool function with Thoth governance.
// Use this variant when your LLM framework passes tool arguments as a
// map[string]any (e.g. OpenAI function calling, Anthropic tool use).
//
// Enforcement semantics are identical to WrapTool.
//
// Example:
//
//	readFile := client.WrapToolFunc("read_file", func(ctx context.Context, args map[string]any) (any, error) {
//	    path, _ := args["path"].(string)
//	    return os.ReadFile(path)
//	})
func (c *Client) WrapToolFunc(name string, fn ToolFunc) ToolFunc {
	wrapped := c.tracer.WrapTool(name, toolFuncAdapter(fn))

	return func(ctx context.Context, args map[string]any) (any, error) {
		result, err := wrapped(ctx, args)
		if err != nil {
			return nil, translateError(err)
		}
		return result, nil
	}
}

// translateError converts internal thoth error types to the public SDK types.
// Unknown error types are passed through unchanged.
func translateError(err error) error {
	if err == nil {
		return nil
	}

	// Internal PolicyViolationError → public PolicyViolationError.
	var pve *ithoth.PolicyViolationError
	if errors.As(err, &pve) {
		if sue, ok := translateStepUpPendingError(pve); ok {
			return sue
		}
		return &PolicyViolationError{
			ToolName:              pve.ToolName,
			Reason:                pve.Reason,
			ViolationID:           pve.ViolationID,
			DecisionReasonCode:    pve.DecisionReasonCode,
			ActionClassification:  pve.ActionClassification,
			AuthorizationDecision: pve.AuthorizationDecision,
			DeferTimeoutSeconds:   pve.DeferTimeoutSeconds,
			StepUpTimeoutSeconds:  pve.StepUpTimeoutSeconds,
			RiskScore:             pve.RiskScore,
			LatencyMs:             pve.LatencyMs,
			PackID:                pve.PackID,
			PackVersion:           pve.PackVersion,
			RuleVersion:           pve.RuleVersion,
			RegulatoryRegimes:     append([]string{}, pve.RegulatoryRegimes...),
			MatchedRuleIDs:        append([]string{}, pve.MatchedRuleIDs...),
			MatchedControlIDs:     append([]string{}, pve.MatchedControlIDs...),
			PolicyReferences:      append([]string{}, pve.PolicyReferences...),
			ModelSignals:          append([]string{}, pve.ModelSignals...),
			Receipt:               cloneAnyMap(pve.Receipt),
		}
	}

	log.Printf("thoth: sdk: unhandled internal error type %T: %v", err, err)
	return err
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

var holdTokenPatterns = [...]*regexp.Regexp{
	regexp.MustCompile(`(?i)hold[_\s-]?token[=:]\s*([A-Za-z0-9._:-]+)`),
	regexp.MustCompile(`(?i)hold[_\s-]?token\s+([A-Za-z0-9._:-]+)`),
	regexp.MustCompile(`(?i)"hold_token"\s*:\s*"([^"]+)"`),
}

func translateStepUpPendingError(pve *ithoth.PolicyViolationError) (*StepUpRequiredError, bool) {
	reason := strings.TrimSpace(pve.Reason)
	if reason == "" {
		return nil, false
	}

	normalized := strings.ToLower(reason)
	if !strings.Contains(normalized, "step-up") && !strings.Contains(normalized, "step up") {
		return nil, false
	}

	// Timeout/deny represent terminal block outcomes and must remain
	// PolicyViolationError for caller handling and audit parity.
	if strings.Contains(normalized, "timeout") ||
		strings.Contains(normalized, "timed out") ||
		strings.Contains(normalized, "denied") ||
		strings.Contains(normalized, "rejected") {
		return nil, false
	}

	holdToken := extractHoldToken(reason)
	if holdToken == "" {
		return nil, false
	}

	return &StepUpRequiredError{
		ToolName:  pve.ToolName,
		HoldToken: holdToken,
		Reason:    reason,
	}, true
}

func extractHoldToken(reason string) string {
	for _, pattern := range holdTokenPatterns {
		match := pattern.FindStringSubmatch(reason)
		if len(match) > 1 {
			token := strings.TrimSpace(match[1])
			token = strings.Trim(token, `"'()[]{}.,;`)
			if token != "" {
				return token
			}
		}
	}
	return ""
}
