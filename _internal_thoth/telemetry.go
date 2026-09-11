package thoth

import "time"

// telemetryEvent is the allowlisted retained representation. Authorization
// requests continue to receive the original event inputs.
type telemetryEvent struct {
	EventID          string          `json:"event_id"`
	TenantID         string          `json:"tenant_id"`
	AgentID          string          `json:"agent_id,omitempty"`
	SessionID        string          `json:"session_id"`
	UserID           string          `json:"user_id"`
	SourceType       SourceType      `json:"source_type"`
	EventType        EventType       `json:"event_type"`
	ToolName         string          `json:"tool_name,omitempty"`
	Content          string          `json:"content"`
	Metadata         map[string]any  `json:"metadata"`
	ApprovedScope    []string        `json:"approved_scope"`
	EnforcementMode  EnforcementMode `json:"enforcement_mode"`
	SessionToolCalls []string        `json:"session_tool_calls"`
	OccurredAt       time.Time       `json:"occurred_at"`
	TTL              int64           `json:"ttl"`
	ViolationID      string          `json:"violation_id,omitempty"`
}

var telemetryStringFields = map[string]struct{}{
	"sdk_language": {}, "environment": {}, "enforcement_trace_id": {},
	"action_attestation_id": {}, "decision_id": {}, "event_phase": {},
	"authorization_decision": {}, "decision_reason_code": {},
	"action_classification": {}, "pack_id": {}, "pack_version": {},
	"result_type": {}, "decision_envelope_version": {},
}

var telemetryNumberFields = map[string]struct{}{
	"duration_ms": {}, "result_size_bytes": {}, "risk_score": {}, "latency_ms": {},
	"rule_version": {}, "defer_timeout_seconds": {}, "step_up_timeout_seconds": {},
}

var telemetryListFields = map[string]struct{}{
	"regulatory_regimes": {}, "matched_rule_ids": {}, "matched_control_ids": {},
	"policy_references": {},
}

func minimalTelemetryEvent(event *BehavioralEvent) telemetryEvent {
	metadata := map[string]any{"telemetry_capture": "minimal"}
	for key := range telemetryStringFields {
		if value, ok := event.Metadata[key].(string); ok {
			metadata[key] = value
		}
	}
	for key := range telemetryNumberFields {
		switch value := event.Metadata[key].(type) {
		case int, int32, int64, float32, float64:
			metadata[key] = value
		}
	}
	for key := range telemetryListFields {
		if value := safeStringList(event.Metadata[key]); value != nil {
			metadata[key] = value
		}
	}
	if receipt := safeReceipt(event.Metadata["receipt"]); receipt != nil {
		metadata["receipt"] = receipt
	}
	if evidence := safeDecisionEvidence(event.Metadata["decision_evidence"]); evidence != nil {
		metadata["decision_evidence"] = evidence
	}
	if event.ToolName != "" {
		metadata["tool_call"] = map[string]any{"name": event.ToolName}
	}
	return telemetryEvent{
		EventID: event.EventID, TenantID: event.TenantID, AgentID: event.AgentID,
		SessionID: event.SessionID, UserID: event.UserID, SourceType: event.SourceType,
		EventType: event.EventType, ToolName: event.ToolName,
		Content: ensureContent("", event.EventType), Metadata: metadata,
		ApprovedScope:    append([]string(nil), event.ApprovedScope...),
		EnforcementMode:  event.EnforcementMode,
		SessionToolCalls: append([]string(nil), event.SessionToolCalls...),
		OccurredAt:       event.OccurredAt, TTL: event.TTL, ViolationID: event.ViolationID,
	}
}

func safeStringList(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		result := make([]string, 0, len(values))
		for _, item := range values {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func safeReceipt(value any) map[string]any {
	source, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := map[string]any{}
	for _, key := range []string{"receipt_id", "decision_id", "signature", "signing_algorithm", "key_id", "schema_version"} {
		if text, ok := source[key].(string); ok {
			result[key] = text
		}
	}
	if decision, ok := source["decision"].(map[string]any); ok {
		safe := map[string]any{}
		for _, key := range []string{"authorization_decision", "decision_reason_code", "outcome"} {
			if text, ok := decision[key].(string); ok {
				safe[key] = text
			}
		}
		if len(safe) > 0 {
			result["decision"] = safe
		}
	}
	return result
}

func safeDecisionEvidence(value any) map[string]any {
	source, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := map[string]any{}
	for key := range telemetryStringFields {
		if text, ok := source[key].(string); ok {
			result[key] = text
		}
	}
	for key := range telemetryNumberFields {
		switch number := source[key].(type) {
		case int, int32, int64, float32, float64:
			result[key] = number
		}
	}
	if policy, ok := source["policy"].(map[string]any); ok {
		safe := map[string]any{}
		for _, key := range []string{"policy_id", "policy_version", "rule_id"} {
			if text, ok := policy[key].(string); ok {
				safe[key] = text
			}
		}
		for _, key := range []string{"matched_rule_ids", "matched_control_ids", "policy_references"} {
			if list := safeStringList(policy[key]); list != nil {
				safe[key] = list
			}
		}
		if len(safe) > 0 {
			result["policy"] = safe
		}
	}
	return result
}
