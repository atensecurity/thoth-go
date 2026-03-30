package thoth

import (
	"context"
	"errors"
	"fmt"
	"log"

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
//
// Fail-open: if the enforcer is unreachable, the tool executes with a warning
// log — agent availability is never sacrificed for observability.
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
		return &PolicyViolationError{
			ToolName:    pve.ToolName,
			Reason:      pve.Reason,
			ViolationID: pve.ViolationID,
		}
	}

	// The internal tracer surfaces step-up timeouts as PolicyViolationError with
	// "step-up auth required" prefix. For the public SDK we surface any step-up
	// scenario that did NOT time out as a StepUpRequiredError so callers can
	// distinguish "blocked" from "pending approval".
	// The internal package encodes this in the PolicyViolationError.Reason field
	// when it wraps an original STEP_UP decision — we forward as-is here since
	// wait/timeout have already been handled inside the tracer.
	log.Printf("thoth: sdk: unhandled internal error type %T: %v", err, err)
	return err
}
