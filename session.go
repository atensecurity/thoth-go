package thoth

import (
	"context"
	"log"

	ithoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

// Session represents an active agent session with its own isolated tool-call
// history and a dedicated Tracer.
type Session struct {
	// ID is the unique session identifier (UUID).
	ID string

	client  *Client
	tracer  *ithoth.Tracer
	emitter ithoth.Emitter
	closed  bool
}

// StartSession creates a new agent session.
func (c *Client) StartSession(ctx context.Context, agentID, sessionID string) (*Session, error) {
	internalCfg := toInternalConfig(c.cfg)
	if agentID != "" {
		internalCfg.AgentID = agentID
	}

	sessCtx := ithoth.NewSessionContext(internalCfg)
	if sessionID != "" {
		sessCtx.SessionID = sessionID
	}

	sessionTracer := ithoth.NewTracer(internalCfg, sessCtx, c.emitter)

	sess := &Session{
		ID:      sessCtx.SessionID,
		client:  c,
		tracer:  sessionTracer,
		emitter: c.emitter,
	}

	if c.emitter != nil {
		ev := ithoth.NewBehavioralEvent(
			internalCfg.AgentID,
			internalCfg.TenantID,
			sessCtx.SessionID,
			ithoth.EventScopeCheck,
			"session_start",
		)
		c.emitter.Emit(&ev)
	}

	log.Printf("thoth: session started (id=%s agent=%s)", sess.ID, internalCfg.AgentID)
	return sess, nil
}

// WrapTool wraps a string-in / string-out tool function scoped to this session.
func (s *Session) WrapTool(
	name string,
	fn func(ctx context.Context, input string) (string, error),
) func(ctx context.Context, input string) (string, error) {
	internalFn := ithoth.ToolFunc(func(ctx context.Context, args ...any) (any, error) {
		var input string
		if len(args) > 0 {
			if str, ok := args[0].(string); ok {
				input = str
			}
		}
		return fn(ctx, input)
	})

	wrapped := s.tracer.WrapTool(name, internalFn)

	return func(ctx context.Context, input string) (string, error) {
		result, err := wrapped(ctx, input)
		if err != nil {
			return "", translateError(err)
		}
		if result == nil {
			return "", nil
		}
		if str, ok := result.(string); ok {
			return str, nil
		}
		return "", nil
	}
}

// WrapToolFunc wraps a map-based tool function scoped to this session.
func (s *Session) WrapToolFunc(name string, fn ToolFunc) ToolFunc {
	wrapped := s.tracer.WrapTool(name, toolFuncAdapter(fn))

	return func(ctx context.Context, args map[string]any) (any, error) {
		result, err := wrapped(ctx, args)
		if err != nil {
			return nil, translateError(err)
		}
		return result, nil
	}
}

// Close emits a session-end event and marks the session as closed.
func (s *Session) Close() {
	if s.closed {
		return
	}
	s.closed = true

	internalCfg := toInternalConfig(s.client.cfg)
	if s.emitter != nil {
		ev := ithoth.NewBehavioralEvent(
			internalCfg.AgentID,
			internalCfg.TenantID,
			s.ID,
			ithoth.EventScopeCheck,
			"session_end",
		)
		s.emitter.Emit(&ev)
	}

	log.Printf("thoth: session closed (id=%s)", s.ID)
}
