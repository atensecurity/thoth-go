package thoth

import (
	"context"

	ithoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

// toolFuncAdapter wraps a map-based ToolFunc as an internal variadic ToolFunc.
// This is the shared adapter used by both Client.WrapToolFunc and Session.WrapToolFunc
// to avoid duplicating the same type-assertion logic in both call sites.
func toolFuncAdapter(fn ToolFunc) ithoth.ToolFunc {
	return ithoth.ToolFunc(func(ctx context.Context, args ...any) (any, error) {
		var m map[string]any
		if len(args) > 0 {
			if cast, ok := args[0].(map[string]any); ok {
				m = cast
			}
		}
		if m == nil {
			m = make(map[string]any)
		}
		return fn(ctx, m)
	})
}
