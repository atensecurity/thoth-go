package thoth

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestDecisionLogOmitsReasonAndHoldToken(t *testing.T) {
	t.Setenv("THOTH_LOG_LEVEL", "debug")
	var output bytes.Buffer
	old := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(old) })

	tracer := &Tracer{session: &SessionContext{SessionID: "session-safe-001"}}
	tracer.logDecision("read:data", "trace-safe-001", "action-safe-001", EnforcementDecision{
		Decision: DecisionStepUp, AuthorizationDecision: "STEP_UP",
		DecisionReasonCode: "approval_required", Reason: "SYNTHETIC-PHI-SECRET-REASON",
		HoldToken: "SYNTHETIC-PHI-SECRET-HOLD",
	}, "enforce")

	rendered := output.String()
	if strings.Contains(rendered, "SYNTHETIC-PHI-SECRET") {
		t.Fatalf("decision log leaked sensitive content: %s", rendered)
	}
	if !strings.Contains(rendered, "approval_required") || !strings.Contains(rendered, "action-safe-001") {
		t.Fatalf("decision log lost safe evidence: %s", rendered)
	}
}
