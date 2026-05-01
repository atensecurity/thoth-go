package thoth

import "fmt"

// PolicyViolationError is returned when the enforcer blocks a tool call.
// Inspect Reason for a human-readable explanation and ViolationID to
// correlate with audit logs in the Thoth dashboard.
type PolicyViolationError struct {
	// ToolName is the name of the tool that was blocked.
	ToolName string
	// Reason is a human-readable explanation of why the policy was violated.
	Reason string
	// ViolationID is the enforcer-assigned identifier for this violation event.
	// Use it to look up the full audit record in the Thoth dashboard.
	ViolationID string
	// DecisionReasonCode is the stable policy reason code emitted by enforcer.
	DecisionReasonCode string
	// ActionClassification is the policy action class (read/write/execute/etc.).
	ActionClassification string
	// AuthorizationDecision is the canonical authorization decision string.
	AuthorizationDecision string
	// DeferTimeoutSeconds is the enforcer-provided suggested retry delay.
	DeferTimeoutSeconds int
	// StepUpTimeoutSeconds is the timeout budget for step-up approval windows.
	StepUpTimeoutSeconds int
	// RiskScore is the model/rule risk score used for policy decisions.
	RiskScore float64
	// LatencyMs is end-to-end policy evaluation latency in milliseconds.
	LatencyMs float64
	// PackID identifies the active policy pack.
	PackID string
	// PackVersion identifies the active pack version.
	PackVersion string
	// RuleVersion identifies the active policy rule version.
	RuleVersion int
	// RegulatoryRegimes indicates the regimes associated with the applied policy.
	RegulatoryRegimes []string
	// MatchedRuleIDs are the matched policy rule identifiers.
	MatchedRuleIDs []string
	// MatchedControlIDs are the matched control identifiers.
	MatchedControlIDs []string
	// PolicyReferences are framework/control references mapped to the decision.
	PolicyReferences []string
	// ModelSignals are explainability signals from deterministic/ML engines.
	ModelSignals []string
	// Receipt is the decision receipt payload when available.
	Receipt map[string]any
}

// Error implements the error interface.
func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("thoth: policy violation blocked tool %q: %s (violation_id=%s)",
		e.ToolName, e.Reason, e.ViolationID)
}

// StepUpRequiredError is returned when the enforcer requires human approval
// before a tool call can proceed and the caller opts not to wait inline.
//
// To resume the call after approval, the approver resolves the HoldToken
// via the Thoth dashboard or API. The original tool call must then be
// retried by the caller.
type StepUpRequiredError struct {
	// ToolName is the name of the tool pending approval.
	ToolName string
	// HoldToken is the opaque token identifying this pending approval request.
	// Pass it to the Thoth step-up API or dashboard to approve or deny.
	HoldToken string
	// Reason is a human-readable explanation of why step-up auth was triggered.
	Reason string
}

// Error implements the error interface.
func (e *StepUpRequiredError) Error() string {
	return fmt.Sprintf("thoth: step-up auth required for tool %q: %s (hold_token=%s)",
		e.ToolName, e.Reason, e.HoldToken)
}
