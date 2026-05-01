package thoth

import "fmt"

// PolicyViolationError is returned when a tool call is blocked by Thoth policy enforcement.
type PolicyViolationError struct {
	ToolName              string
	Reason                string
	ViolationID           string
	DecisionReasonCode    string
	ActionClassification  string
	AuthorizationDecision string
	DeferTimeoutSeconds   int
	StepUpTimeoutSeconds  int
	RiskScore             float64
	LatencyMs             float64
	PackID                string
	PackVersion           string
	RuleVersion           int
	RegulatoryRegimes     []string
	MatchedRuleIDs        []string
	MatchedControlIDs     []string
	PolicyReferences      []string
	ModelSignals          []string
	Receipt               map[string]any
}

// Error implements the error interface.
func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("thoth: blocked tool %q: %s", e.ToolName, e.Reason)
}
