package thoth_test

import (
	"testing"
	"time"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

func TestEnforcementModeConstants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode thoth.EnforcementMode
		want string
	}{
		{"observe", thoth.Observe, "observe"},
		{"step_up", thoth.StepUp, "step_up"},
		{"block", thoth.Block, "block"},
		{"progressive", thoth.Progressive, "progressive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if string(tc.mode) != tc.want {
				t.Errorf("got %q, want %q", tc.mode, tc.want)
			}
		})
	}
}

func TestSourceTypeConstants(t *testing.T) {
	t.Parallel()
	if string(thoth.SourceAgent) != "agent" {
		t.Errorf("SourceAgent = %q, want %q", thoth.SourceAgent, "agent")
	}
	if string(thoth.SourceHuman) != "human" {
		t.Errorf("SourceHuman = %q, want %q", thoth.SourceHuman, "human")
	}
}

func TestEventTypeConstants(t *testing.T) {
	t.Parallel()
	cases := map[thoth.EventType]string{
		thoth.EventToolCall:   "tool_call",
		thoth.EventTokenSpend: "token_spend",
		thoth.EventScopeCheck: "scope_check",
	}
	for k, want := range cases {
		if string(k) != want {
			t.Errorf("EventType %q != %q", k, want)
		}
	}
}

func TestDecisionTypeConstants(t *testing.T) {
	t.Parallel()
	cases := map[thoth.DecisionType]string{
		thoth.DecisionAllow:   "ALLOW",
		thoth.DecisionBlock:   "BLOCK",
		thoth.DecisionStepUp:  "STEP_UP",
		thoth.DecisionObserve: "observe",
	}
	for k, want := range cases {
		if string(k) != want {
			t.Errorf("DecisionType %q != %q", k, want)
		}
	}
}

func TestBehavioralEventTTL(t *testing.T) {
	t.Parallel()
	ev := thoth.NewBehavioralEvent("agent-1", "tenant-1", "sess-1", thoth.EventToolCall, "read_file")
	if ev.TTL.IsZero() {
		t.Fatal("TTL must not be zero")
	}
	approxExpiry := time.Now().Add(90 * 24 * time.Hour)
	diff := ev.TTL.Sub(approxExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("TTL diff from 90d = %v, expected near zero", diff)
	}
}

func TestBehavioralEventFields(t *testing.T) {
	t.Parallel()
	ev := thoth.NewBehavioralEvent("agent-1", "tenant-1", "sess-1", thoth.EventToolCall, "write_slack")
	if ev.AgentID != "agent-1" {
		t.Errorf("AgentID = %q", ev.AgentID)
	}
	if ev.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q", ev.TenantID)
	}
	if ev.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", ev.SessionID)
	}
	if ev.EventType != thoth.EventToolCall {
		t.Errorf("EventType = %q", ev.EventType)
	}
	if ev.ToolName != "write_slack" {
		t.Errorf("ToolName = %q", ev.ToolName)
	}
	if ev.EventID == "" {
		t.Error("EventID must be set")
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp must be set")
	}
}

func TestThothConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{
		AgentID:  "test-agent",
		TenantID: "test-tenant",
	}
	cfg = thoth.ApplyConfigDefaults(cfg)
	if cfg.EnforcerURL != "http://enforcer:8080" {
		t.Errorf("EnforcerURL = %q, want default", cfg.EnforcerURL)
	}
	if cfg.Enforcement != thoth.Progressive {
		t.Errorf("Enforcement = %q, want Progressive", cfg.Enforcement)
	}
}
