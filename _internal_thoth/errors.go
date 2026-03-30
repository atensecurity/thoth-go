package thoth

import "fmt"

// PolicyViolationError is returned when a tool call is blocked by Thoth policy enforcement.
type PolicyViolationError struct {
	ToolName    string
	Reason      string
	ViolationID string
}

// Error implements the error interface.
func (e *PolicyViolationError) Error() string {
	return fmt.Sprintf("thoth: blocked tool %q: %s", e.ToolName, e.Reason)
}
