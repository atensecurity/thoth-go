package thoth

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ToolFunc is the function signature for an agent tool.
type ToolFunc func(ctx context.Context, args ...any) (any, error)

// Tracer wraps individual tool functions with pre-enforcement checks and post-execution
// event emission. It is the core execution component of the Thoth SDK.
type Tracer struct {
	cfg           Config
	session       *SessionContext
	emitter       Emitter
	enforcer      *EnforcerClient
	stepUp        *StepUpClient
	stepUpTimeout time.Duration
	tools         map[string]ToolFunc
}

const defaultStepUpTimeout = 30 * time.Second

// NewTracer creates a Tracer wired to the provided config, session, and optional emitter.
func NewTracer(cfg Config, session *SessionContext, emitter Emitter) *Tracer {
	cfg = ApplyConfigDefaults(cfg)
	return &Tracer{
		cfg:           cfg,
		session:       session,
		emitter:       emitter,
		enforcer:      NewEnforcerClient(cfg.EnforcerURL, cfg.APIKey),
		stepUp:        NewStepUpClient(cfg.EnforcerURL, cfg.APIKey, 0),
		stepUpTimeout: defaultStepUpTimeout,
		tools:         make(map[string]ToolFunc),
	}
}

// NewTracerWithStepUpTimeout creates a Tracer with a custom step-up polling timeout
// in milliseconds. Intended for testing to avoid long waits.
func NewTracerWithStepUpTimeout(cfg Config, session *SessionContext, emitter Emitter, stepUpTimeoutMS int) *Tracer {
	t := NewTracer(cfg, session, emitter)
	t.stepUpTimeout = time.Duration(stepUpTimeoutMS) * time.Millisecond
	interval := time.Duration(stepUpTimeoutMS/5) * time.Millisecond
	if interval == 0 {
		interval = time.Millisecond
	}
	t.stepUp = NewStepUpClient(cfg.EnforcerURL, cfg.APIKey, interval)
	return t
}

// WrapTool wraps fn with pre-enforcement and post-emission logic.
func (t *Tracer) WrapTool(name string, fn ToolFunc) ToolFunc {
	wrapped := t.buildWrapped(name, fn)
	t.tools[name] = wrapped
	return wrapped
}

// Call invokes a tool registered via WrapTool by name.
func (t *Tracer) Call(ctx context.Context, name string, args ...any) (any, error) {
	fn, ok := t.tools[name]
	if !ok {
		return nil, fmt.Errorf("thoth: tool %q not registered", name)
	}
	return fn(ctx, args...)
}

// ToolNames returns the names of all tools registered on this tracer.
func (t *Tracer) ToolNames() []string {
	names := make([]string, 0, len(t.tools))
	for name := range t.tools {
		names = append(names, name)
	}
	return names
}

func (t *Tracer) buildWrapped(name string, fn ToolFunc) ToolFunc {
	return func(ctx context.Context, args ...any) (any, error) {
		if t.cfg.Enforcement == Observe {
			dec, err := t.enforcer.Check(ctx, CheckRequest{
				ToolName:         name,
				SessionID:        t.session.SessionID,
				AgentID:          t.cfg.AgentID,
				TenantID:         t.cfg.TenantID,
				UserID:           t.cfg.UserID,
				ApprovedScope:    t.cfg.ApprovedScope,
				EnforcementMode:  t.cfg.Enforcement,
				SessionToolCalls: t.session.ToolCallsCopy(),
			})
			if err != nil {
				log.Printf("thoth: observe: enforcer unavailable for %q: %v", name, err)
			} else {
				log.Printf("thoth: observe: tool %q decision=%s (session=%s)", name, dec.Decision, t.session.SessionID)
			}
			return t.runTool(ctx, name, fn, args)
		}

		dec, err := t.enforcer.Check(ctx, CheckRequest{
			ToolName:         name,
			SessionID:        t.session.SessionID,
			AgentID:          t.cfg.AgentID,
			TenantID:         t.cfg.TenantID,
			UserID:           t.cfg.UserID,
			ApprovedScope:    t.cfg.ApprovedScope,
			EnforcementMode:  t.cfg.Enforcement,
			SessionToolCalls: t.session.ToolCallsCopy(),
		})
		if err != nil {
			log.Printf("thoth: warn: enforcer check failed for %q: %v", name, err)
			dec = allowDecision
		}

		switch dec.Decision {
		case DecisionBlock:
			return nil, &PolicyViolationError{
				ToolName:    name,
				Reason:      dec.Reason,
				ViolationID: dec.ViolationID,
			}
		case DecisionStepUp:
			stepCtx, cancel := context.WithTimeout(ctx, t.stepUpTimeout)
			defer cancel()
			stepDec := t.stepUp.Wait(stepCtx, dec.HoldToken)
			if stepDec.Decision == DecisionBlock {
				return nil, &PolicyViolationError{
					ToolName:    name,
					Reason:      fmt.Sprintf("step-up auth required: %s", stepDec.Reason),
					ViolationID: dec.ViolationID,
				}
			}
		}

		return t.runTool(ctx, name, fn, args)
	}
}

func (t *Tracer) runTool(ctx context.Context, name string, fn ToolFunc, args []any) (any, error) {
	result, toolErr := fn(ctx, args...)
	t.session.RecordToolCall(name)
	if t.emitter != nil {
		ev := NewBehavioralEvent(t.cfg.AgentID, t.cfg.TenantID, t.session.SessionID, EventToolCall, name)
		t.emitter.Emit(&ev)
	}
	return result, toolErr
}
