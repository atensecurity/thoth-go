package thoth

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
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
		sessionToolCalls := withCurrentToolCall(t.session.ToolCallsCopy(), name)
		checkReq := CheckRequest{
			ToolName:  name,
			SessionID: t.session.SessionID,
			AgentID:   t.cfg.AgentID,
			TenantID:  t.cfg.TenantID,
			UserID:    t.cfg.UserID,
			IdentityBinding: resolveIdentityBinding(
				t.cfg.IdentityBinding,
				t.cfg.AgentID,
				t.cfg.TenantID,
				t.cfg.UserID,
			),
			ApprovedScope:    t.cfg.ApprovedScope,
			EnforcementMode:  t.cfg.Enforcement,
			SessionToolCalls: sessionToolCalls,
			ToolArgs:         normalizeToolArgs(args),
			Environment:      t.cfg.Environment,
			EnforcementTraceID: resolveEnforcementTraceID(
				t.cfg.EnforcementTraceID,
				t.session.SessionID,
			),
			SessionIntent: t.cfg.SessionIntent,
		}
		t.emitLifecycleEvent(name, EventToolCallPre, "tool invocation requested", "", sessionToolCalls, map[string]any{
			"enforcement_trace_id": checkReq.EnforcementTraceID,
			"environment":          checkReq.Environment,
		})

		if t.cfg.Enforcement == Observe {
			dec, err := t.enforcer.Check(ctx, checkReq)
			if err != nil {
				log.Printf("thoth: observe: enforcer unavailable for %q: %v", name, err)
			} else {
				t.logDecision(name, checkReq.EnforcementTraceID, dec, "observe")
			}
			return t.runTool(ctx, name, fn, args, sessionToolCalls)
		}

		dec, err := t.enforcer.Check(ctx, checkReq)
		if err != nil {
			log.Printf("thoth: warn: enforcer check failed for %q: %v", name, err)
			dec = fallbackDecision
		}
		t.logDecision(name, checkReq.EnforcementTraceID, dec, "enforce")
		effectiveArgs := args

		switch dec.Decision {
		case DecisionBlock:
			t.emitBlockEvent(name, dec, sessionToolCalls)
			return nil, &PolicyViolationError{
				ToolName:             name,
				Reason:               dec.Reason,
				ViolationID:          dec.ViolationID,
				DecisionReasonCode:   dec.DecisionReasonCode,
				ActionClassification: dec.ActionClassification,
			}
		case DecisionDefer:
			t.emitBlockEvent(name, dec, sessionToolCalls)
			reason := dec.DeferReason
			if reason == "" {
				reason = dec.Reason
			}
			if reason == "" {
				reason = "deferred pending additional context"
			}
			if dec.DeferTimeoutSeconds > 0 {
				reason = fmt.Sprintf("%s (retry in %ds)", reason, dec.DeferTimeoutSeconds)
			}
			return nil, &PolicyViolationError{
				ToolName:             name,
				Reason:               reason,
				ViolationID:          dec.ViolationID,
				DecisionReasonCode:   dec.DecisionReasonCode,
				ActionClassification: dec.ActionClassification,
			}
		case DecisionModify:
			effectiveArgs = applyModifiedArgs(args, dec.ModifiedToolArgs)
		case DecisionStepUp:
			stepCtx, cancel := context.WithTimeout(ctx, t.stepUpTimeout)
			defer cancel()
			stepDec := t.stepUp.Wait(stepCtx, dec.HoldToken)
			t.logDecision(name, checkReq.EnforcementTraceID, stepDec, "step_up_resolved")
			if stepDec.Decision == DecisionBlock {
				t.emitBlockEvent(name, stepDec, sessionToolCalls)
				return nil, &PolicyViolationError{
					ToolName:             name,
					Reason:               fmt.Sprintf("step-up auth required: %s", stepDec.Reason),
					ViolationID:          dec.ViolationID,
					DecisionReasonCode:   coalesceNonEmpty(stepDec.DecisionReasonCode, dec.DecisionReasonCode),
					ActionClassification: coalesceNonEmpty(stepDec.ActionClassification, dec.ActionClassification),
				}
			}
		}

		return t.runTool(ctx, name, fn, effectiveArgs, sessionToolCalls)
	}
}

func (t *Tracer) logDecision(toolName, traceID string, decision EnforcementDecision, phase string) {
	log.Printf(
		"thoth: %s decision tool=%q decision=%s authorization_decision=%q reason_code=%q reason=%q trace_id=%q session_id=%q",
		phase,
		toolName,
		decision.Decision,
		decision.AuthorizationDecision,
		decision.DecisionReasonCode,
		decision.Reason,
		traceID,
		t.session.SessionID,
	)
}

func coalesceNonEmpty(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

func applyModifiedArgs(args []any, modified map[string]any) []any {
	if len(modified) == 0 {
		return args
	}
	if values, ok := modified["args"].([]any); ok {
		return values
	}

	if len(args) == 1 {
		if _, ok := args[0].(map[string]any); ok {
			return []any{modified}
		}
		if value, ok := modified["arg0"]; ok {
			return []any{value}
		}
		if value, ok := modified["input"]; ok {
			return []any{value}
		}
	}

	indexed := map[int]any{}
	for key, value := range modified {
		if !strings.HasPrefix(key, "arg") {
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(key, "arg"))
		if err != nil || index < 0 {
			continue
		}
		indexed[index] = value
	}
	if len(indexed) == 0 {
		return args
	}

	indices := make([]int, 0, len(indexed))
	for index := range indexed {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	if indices[0] != 0 || indices[len(indices)-1] != len(indices)-1 {
		return args
	}

	out := make([]any, len(indices))
	for _, index := range indices {
		out[index] = indexed[index]
	}
	return out
}

func normalizeToolArgs(args []any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	if len(args) == 1 {
		if m, ok := args[0].(map[string]any); ok {
			return m
		}
	}

	out := make(map[string]any, len(args))
	for i, arg := range args {
		out[fmt.Sprintf("arg%d", i)] = arg
	}
	return out
}

func resolveEnforcementTraceID(configTraceID, sessionID string) string {
	if configTraceID != "" {
		return configTraceID
	}
	return sessionID
}

func resolveIdentityBinding(
	configBinding map[string]any,
	agentID, tenantID, userID string,
) map[string]any {
	if len(configBinding) > 0 {
		out := make(map[string]any, len(configBinding))
		for key, value := range configBinding {
			out[key] = value
		}
		return out
	}

	out := map[string]any{
		"agent_id":  agentID,
		"tenant_id": tenantID,
	}
	if userID != "" {
		out["user_id"] = userID
	}
	return out
}

func withCurrentToolCall(toolCalls []string, toolName string) []string {
	out := make([]string, 0, len(toolCalls)+1)
	out = append(out, toolCalls...)
	out = append(out, toolName)
	if len(out) > sessionToolCallsCap {
		out = append([]string{}, out[len(out)-sessionToolCallsCap:]...)
	}
	return out
}

func (t *Tracer) runTool(ctx context.Context, name string, fn ToolFunc, args []any, sessionToolCalls []string) (any, error) {
	result, toolErr := fn(ctx, args...)
	t.session.RecordToolCall(name)
	if toolErr != nil {
		return result, toolErr
	}
	eventMetadata := map[string]any{
		"result_type": fmt.Sprintf("%T", result),
	}
	t.emitLifecycleEvent(name, EventToolCallPost, "tool invocation completed", "", sessionToolCalls, eventMetadata)
	return result, toolErr
}

func (t *Tracer) emitBlockEvent(name string, decision EnforcementDecision, sessionToolCalls []string) {
	reason := decision.Reason
	if reason == "" {
		reason = decision.DeferReason
	}
	metadata := map[string]any{
		"decision": decision.Decision,
	}
	if decision.DecisionReasonCode != "" {
		metadata["decision_reason_code"] = decision.DecisionReasonCode
	}
	if decision.ActionClassification != "" {
		metadata["action_classification"] = decision.ActionClassification
	}
	if decision.AuthorizationDecision != "" {
		metadata["authorization_decision"] = decision.AuthorizationDecision
	}
	if decision.DeferTimeoutSeconds > 0 {
		metadata["defer_timeout_seconds"] = decision.DeferTimeoutSeconds
	}
	if decision.StepUpTimeoutSeconds > 0 {
		metadata["step_up_timeout_seconds"] = decision.StepUpTimeoutSeconds
	}
	t.emitLifecycleEvent(name, EventToolCallBlock, reason, decision.ViolationID, sessionToolCalls, metadata)
}

func (t *Tracer) emitLifecycleEvent(
	toolName string,
	eventType EventType,
	content string,
	violationID string,
	sessionToolCalls []string,
	metadata map[string]any,
) {
	if t.emitter == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	ev := NewBehavioralEvent(BehavioralEventInput{
		AgentID:          t.cfg.AgentID,
		TenantID:         t.cfg.TenantID,
		SessionID:        t.session.SessionID,
		UserID:           t.cfg.UserID,
		SourceType:       SourceAgentToolCall,
		EventType:        eventType,
		ToolName:         toolName,
		Content:          content,
		Metadata:         metadata,
		ApprovedScope:    append([]string{}, t.cfg.ApprovedScope...),
		EnforcementMode:  t.cfg.Enforcement,
		SessionToolCalls: append([]string{}, sessionToolCalls...),
		ViolationID:      violationID,
	})
	t.emitter.Emit(&ev)
}
