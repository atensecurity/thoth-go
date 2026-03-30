package thoth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

func TestPolicyViolationError_Error(t *testing.T) {
	t.Parallel()
	err := &thoth.PolicyViolationError{
		ToolName:    "write_db",
		Reason:      "outside approved scope",
		ViolationID: "vio-123",
	}
	got := err.Error()
	want := `thoth: blocked tool "write_db": outside approved scope`
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestPolicyViolationError_ErrorsAs(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("outer: %w", &thoth.PolicyViolationError{
		ToolName: "x",
		Reason:   "y",
	})
	var pve *thoth.PolicyViolationError
	if !errors.As(wrapped, &pve) {
		t.Fatal("errors.As should unwrap PolicyViolationError")
	}
	if pve.ToolName != "x" {
		t.Errorf("ToolName = %q", pve.ToolName)
	}
}
