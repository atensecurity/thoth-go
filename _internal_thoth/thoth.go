package thoth

import (
	"context"
	"log"
	"reflect"
)

// contextType is the reflection type of context.Context.
var contextType = reflect.TypeOf((*context.Context)(nil)).Elem()

// matchesToolFunc reports whether method m has the same signature as ToolFunc:
//
//	func(ctx context.Context, args ...any) (any, error)
//
// i.e. receiver + (context.Context, ...any) → (any, error).
func matchesToolFunc(m reflect.Method) bool {
	mt := m.Type // includes receiver as first param
	// Total params: receiver, ctx, variadic any → 3 (variadic counts as one in Type).
	// Results: any, error → 2.
	if mt.NumIn() != 3 || mt.NumOut() != 2 {
		return false
	}
	// Param[1] must implement context.Context.
	if !mt.In(1).Implements(contextType) {
		return false
	}
	// Param[2] must be variadic []any.
	if !mt.IsVariadic() {
		return false
	}
	// In variadic methods, In(n-1) is the slice type, e.g. []interface{}.
	if mt.In(2).Kind() != reflect.Slice {
		return false
	}
	elemType := mt.In(2).Elem()
	if elemType.Kind() != reflect.Interface {
		return false
	}
	// Out[0] must be any (interface{}).
	if mt.Out(0).Kind() != reflect.Interface {
		return false
	}
	// Out[1] must be the error interface.
	errType := reflect.TypeOf((*error)(nil)).Elem()
	return mt.Out(1).Implements(errType)
}

// Instrument discovers all ToolFunc-compatible methods on agent, wraps each with
// Thoth enforcement and event emission, and returns a *Tracer whose tool registry
// holds the wrapped functions.
//
// Call tools via the returned tracer:
//
//	tracer := thoth.Instrument(myAgent, cfg)
//	result, err := tracer.Call(ctx, "ReadInvoices", arg1, arg2)
//
// Because Go does not allow replacing methods at runtime, the original agent is not
// modified. The caller must route tool invocations through the returned *Tracer to
// benefit from governance. If the agent has no ToolFunc-compatible methods, a tracer
// with an empty tool registry is returned (callers can still register tools manually
// via tracer.WrapTool).
//
// When APIKey is set in cfg, an HTTPEmitter is created for event emission. Callers
// requiring a custom Emitter should use NewTracer directly.
func Instrument(agent any, cfg Config) *Tracer {
	cfg = ApplyConfigDefaults(cfg)
	sess := NewSessionContext(cfg)

	// Create an HTTP emitter for event emission using the hosted API.
	var emitter Emitter
	if cfg.APIKey != "" {
		emitter = NewHTTPEmitterWithEventIngestToken(cfg.APIURL, cfg.APIKey, cfg.EventIngestToken)
	}

	tracer := NewTracer(cfg, sess, emitter)

	if agent == nil {
		return tracer
	}

	v := reflect.ValueOf(agent)
	t := v.Type()

	wrapped := 0
	for i := 0; i < t.NumMethod(); i++ {
		method := t.Method(i)
		if !matchesToolFunc(method) {
			continue
		}
		// Capture method value per iteration to avoid closure-over-loop-variable.
		methodVal := v.MethodByName(method.Name)
		methodName := method.Name
		tracer.WrapTool(methodName, func(ctx context.Context, args ...any) (any, error) {
			// Build the args slice for CallSlice: [ctx, []any{args...}].
			// CallSlice requires the final argument to be a slice matching the
			// variadic element type — here []interface{}{args...}.
			anySlice := make([]any, len(args))
			copy(anySlice, args)
			callArgs := []reflect.Value{
				reflect.ValueOf(ctx),
				reflect.ValueOf(anySlice),
			}
			results := methodVal.CallSlice(callArgs)
			var result any
			// results[0] is interface{} — only call Interface() when non-nil.
			if r0 := results[0]; r0.Kind() != reflect.Invalid && (r0.Kind() != reflect.Interface || !r0.IsNil()) {
				result = r0.Interface()
			}
			var err error
			if r1 := results[1]; r1.Kind() != reflect.Invalid && (r1.Kind() != reflect.Interface || !r1.IsNil()) {
				err = r1.Interface().(error)
			}
			return result, err
		})
		wrapped++
	}

	if wrapped == 0 {
		log.Printf("thoth: Instrument: no ToolFunc-compatible methods found on %T", agent)
	} else {
		log.Printf("thoth: Instrument: wrapped %d methods on %T", wrapped, agent)
	}

	return tracer
}
