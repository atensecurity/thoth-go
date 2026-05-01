package thoth

import (
	"context"
	"encoding/json"
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
		baseMetadata := t.baseToolMetadata(
			name,
			checkReq.ToolArgs,
			checkReq.EnforcementTraceID,
			checkReq.Environment,
		)
		t.emitLifecycleEvent(
			name,
			EventToolCallPre,
			"tool invocation requested",
			"",
			sessionToolCalls,
			mergeMetadata(baseMetadata, map[string]any{"event_phase": "pre"}),
		)
		startedAt := time.Now()

		if t.cfg.Enforcement == Observe {
			var finalDecision *EnforcementDecision
			dec, err := t.enforcer.Check(ctx, checkReq)
			if err != nil {
				log.Printf("thoth: observe: enforcer unavailable for %q: %v", name, err)
			} else {
				t.logDecision(name, checkReq.EnforcementTraceID, dec, "observe")
				finalDecision = &dec
			}
			return t.runTool(ctx, name, fn, args, sessionToolCalls, startedAt, finalDecision, baseMetadata)
		}

		dec, err := t.enforcer.Check(ctx, checkReq)
		if err != nil {
			log.Printf("thoth: warn: enforcer check failed for %q: %v", name, err)
			dec = fallbackDecision
		}
		t.logDecision(name, checkReq.EnforcementTraceID, dec, "enforce")
		effectiveArgs := args
		finalDecision := dec

		switch dec.Decision {
		case DecisionBlock:
			t.emitBlockEvent(name, dec, sessionToolCalls, startedAt, baseMetadata)
			return nil, policyViolationFromDecision(name, dec.Reason, dec)
		case DecisionDefer:
			t.emitBlockEvent(name, dec, sessionToolCalls, startedAt, baseMetadata)
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
			return nil, policyViolationFromDecision(name, reason, dec)
		case DecisionModify:
			effectiveArgs = applyModifiedArgs(args, dec.ModifiedToolArgs)
		case DecisionStepUp:
			stepCtx, cancel := context.WithTimeout(ctx, t.stepUpTimeout)
			defer cancel()
			stepDec := t.stepUp.Wait(stepCtx, dec.HoldToken)
			t.logDecision(name, checkReq.EnforcementTraceID, stepDec, "step_up_resolved")
			finalDecision = stepDec
			if stepDec.Decision == DecisionBlock {
				t.emitBlockEvent(name, stepDec, sessionToolCalls, startedAt, baseMetadata)
				merged := mergeDecisionContext(stepDec, dec)
				merged.Reason = fmt.Sprintf("step-up auth required: %s", stepDec.Reason)
				return nil, policyViolationFromDecision(name, merged.Reason, merged)
			}
			if stepDec.Decision == DecisionDefer {
				t.emitBlockEvent(name, stepDec, sessionToolCalls, startedAt, baseMetadata)
				reason := stepDec.DeferReason
				if reason == "" {
					reason = stepDec.Reason
				}
				if reason == "" {
					reason = "deferred pending additional context"
				}
				if stepDec.DeferTimeoutSeconds > 0 {
					reason = fmt.Sprintf("%s (retry in %ds)", reason, stepDec.DeferTimeoutSeconds)
				}
				merged := mergeDecisionContext(stepDec, dec)
				return nil, policyViolationFromDecision(name, reason, merged)
			}
			if stepDec.Decision == DecisionStepUp {
				unresolved := mergeDecisionContext(stepDec, dec)
				unresolved.Reason = coalesceNonEmpty(unresolved.Reason, "step-up unresolved")
				t.emitBlockEvent(name, unresolved, sessionToolCalls, startedAt, baseMetadata)
				return nil, policyViolationFromDecision(name, unresolved.Reason, unresolved)
			}
			if stepDec.Decision == DecisionModify {
				effectiveArgs = applyModifiedArgs(args, stepDec.ModifiedToolArgs)
			}
		}

		return t.runTool(
			ctx,
			name,
			fn,
			effectiveArgs,
			sessionToolCalls,
			startedAt,
			&finalDecision,
			baseMetadata,
		)
	}
}

func (t *Tracer) logDecision(toolName, traceID string, decision EnforcementDecision, phase string) {
	if !shouldLogDecisionDebug() {
		return
	}

	log.Printf(
		"thoth: %s decision tool=%q decision=%s authorization_decision=%q reason_code=%q reason=%q hold_token=%q trace_id=%q session_id=%q",
		phase,
		toolName,
		decision.Decision,
		decision.AuthorizationDecision,
		decision.DecisionReasonCode,
		decision.Reason,
		decision.HoldToken,
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

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func cloneMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func mergeDecisionContext(primary, fallback EnforcementDecision) EnforcementDecision {
	merged := primary
	merged.ViolationID = coalesceNonEmpty(merged.ViolationID, fallback.ViolationID)
	merged.AuthorizationDecision = coalesceNonEmpty(merged.AuthorizationDecision, fallback.AuthorizationDecision)
	merged.DecisionReasonCode = coalesceNonEmpty(merged.DecisionReasonCode, fallback.DecisionReasonCode)
	merged.ActionClassification = coalesceNonEmpty(merged.ActionClassification, fallback.ActionClassification)
	merged.PackID = coalesceNonEmpty(merged.PackID, fallback.PackID)
	merged.PackVersion = coalesceNonEmpty(merged.PackVersion, fallback.PackVersion)
	if merged.RuleVersion == 0 {
		merged.RuleVersion = fallback.RuleVersion
	}
	if merged.RiskScore == 0 && fallback.RiskScore != 0 {
		merged.RiskScore = fallback.RiskScore
	}
	if merged.LatencyMs == 0 && fallback.LatencyMs != 0 {
		merged.LatencyMs = fallback.LatencyMs
	}
	if len(merged.RegulatoryRegimes) == 0 {
		merged.RegulatoryRegimes = cloneStringSlice(fallback.RegulatoryRegimes)
	}
	if len(merged.MatchedRuleIDs) == 0 {
		merged.MatchedRuleIDs = cloneStringSlice(fallback.MatchedRuleIDs)
	}
	if len(merged.MatchedControlIDs) == 0 {
		merged.MatchedControlIDs = cloneStringSlice(fallback.MatchedControlIDs)
	}
	if len(merged.PolicyReferences) == 0 {
		merged.PolicyReferences = cloneStringSlice(fallback.PolicyReferences)
	}
	if len(merged.ModelSignals) == 0 {
		merged.ModelSignals = cloneStringSlice(fallback.ModelSignals)
	}
	if len(merged.Receipt) == 0 {
		merged.Receipt = cloneMap(fallback.Receipt)
	}
	return merged
}

func policyViolationFromDecision(toolName, reason string, decision EnforcementDecision) *PolicyViolationError {
	authDecision := coalesceNonEmpty(decision.AuthorizationDecision, string(decision.Decision))
	return &PolicyViolationError{
		ToolName:              toolName,
		Reason:                reason,
		ViolationID:           decision.ViolationID,
		DecisionReasonCode:    decision.DecisionReasonCode,
		ActionClassification:  decision.ActionClassification,
		AuthorizationDecision: authDecision,
		DeferTimeoutSeconds:   decision.DeferTimeoutSeconds,
		StepUpTimeoutSeconds:  decision.StepUpTimeoutSeconds,
		RiskScore:             decision.RiskScore,
		LatencyMs:             decision.LatencyMs,
		PackID:                decision.PackID,
		PackVersion:           decision.PackVersion,
		RuleVersion:           decision.RuleVersion,
		RegulatoryRegimes:     cloneStringSlice(decision.RegulatoryRegimes),
		MatchedRuleIDs:        cloneStringSlice(decision.MatchedRuleIDs),
		MatchedControlIDs:     cloneStringSlice(decision.MatchedControlIDs),
		PolicyReferences:      cloneStringSlice(decision.PolicyReferences),
		ModelSignals:          cloneStringSlice(decision.ModelSignals),
		Receipt:               cloneMap(decision.Receipt),
	}
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

func (t *Tracer) runTool(
	ctx context.Context,
	name string,
	fn ToolFunc,
	args []any,
	sessionToolCalls []string,
	startedAt time.Time,
	finalDecision *EnforcementDecision,
	baseMetadata map[string]any,
) (any, error) {
	result, toolErr := fn(ctx, args...)
	t.session.RecordToolCall(name)
	if toolErr != nil {
		return result, toolErr
	}
	eventMetadata := mergeMetadata(baseMetadata, decisionMetadata(finalDecision))
	eventMetadata["event_phase"] = "post"
	eventMetadata["duration_ms"] = time.Since(startedAt).Milliseconds()
	eventMetadata["result_type"] = fmt.Sprintf("%T", result)
	if size := payloadSizeBytes(result); size > 0 {
		eventMetadata["result_size_bytes"] = size
	}
	t.emitLifecycleEvent(name, EventToolCallPost, "tool invocation completed", "", sessionToolCalls, eventMetadata)
	return result, toolErr
}

func (t *Tracer) emitBlockEvent(
	name string,
	decision EnforcementDecision,
	sessionToolCalls []string,
	startedAt time.Time,
	baseMetadata map[string]any,
) {
	reason := decision.Reason
	if reason == "" {
		reason = decision.DeferReason
	}
	metadata := mergeMetadata(baseMetadata, decisionMetadata(&decision))
	metadata["event_phase"] = "block"
	metadata["duration_ms"] = time.Since(startedAt).Milliseconds()
	t.emitLifecycleEvent(name, EventToolCallBlock, reason, decision.ViolationID, sessionToolCalls, metadata)
}

func (t *Tracer) baseToolMetadata(
	toolName string,
	toolArgs map[string]any,
	enforcementTraceID string,
	environment string,
) map[string]any {
	return map[string]any{
		"sdk_language":         "go",
		"environment":          environment,
		"enforcement_trace_id": enforcementTraceID,
		"tool_call": map[string]any{
			"name":      toolName,
			"arguments": toolArgs,
		},
		"tool_args": toolArgs,
	}
}

func decisionMetadata(decision *EnforcementDecision) map[string]any {
	if decision == nil {
		return map[string]any{}
	}
	metadata := map[string]any{}
	authDecision := decision.AuthorizationDecision
	if authDecision == "" {
		authDecision = string(decision.Decision)
	}
	if authDecision != "" {
		metadata["authorization_decision"] = authDecision
	}
	if decision.DecisionReasonCode != "" {
		metadata["decision_reason_code"] = decision.DecisionReasonCode
	}
	if decision.ActionClassification != "" {
		metadata["action_classification"] = decision.ActionClassification
	}
	if decision.DeferTimeoutSeconds > 0 {
		metadata["defer_timeout_seconds"] = decision.DeferTimeoutSeconds
	}
	if decision.StepUpTimeoutSeconds > 0 {
		metadata["step_up_timeout_seconds"] = decision.StepUpTimeoutSeconds
	}
	if decision.RiskScore != 0 {
		metadata["risk_score"] = decision.RiskScore
	}
	if decision.LatencyMs != 0 {
		metadata["latency_ms"] = decision.LatencyMs
	}
	if decision.PackID != "" {
		metadata["pack_id"] = decision.PackID
	}
	if decision.PackVersion != "" {
		metadata["pack_version"] = decision.PackVersion
	}
	if decision.RuleVersion != 0 {
		metadata["rule_version"] = decision.RuleVersion
	}
	if len(decision.RegulatoryRegimes) > 0 {
		metadata["regulatory_regimes"] = cloneStringSlice(decision.RegulatoryRegimes)
	}
	if len(decision.MatchedRuleIDs) > 0 {
		metadata["matched_rule_ids"] = cloneStringSlice(decision.MatchedRuleIDs)
	}
	if len(decision.MatchedControlIDs) > 0 {
		metadata["matched_control_ids"] = cloneStringSlice(decision.MatchedControlIDs)
	}
	if len(decision.PolicyReferences) > 0 {
		metadata["policy_references"] = cloneStringSlice(decision.PolicyReferences)
	}
	if len(decision.ModelSignals) > 0 {
		metadata["model_signals"] = cloneStringSlice(decision.ModelSignals)
	}
	if len(decision.Receipt) > 0 {
		metadata["receipt"] = cloneMap(decision.Receipt)
	}
	return metadata
}

func mergeMetadata(base map[string]any, extras map[string]any) map[string]any {
	merged := map[string]any{}
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extras {
		merged[key] = value
	}
	return merged
}

func payloadSizeBytes(value any) int {
	payload, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	return len(payload)
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
