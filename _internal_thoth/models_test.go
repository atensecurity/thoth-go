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
	if string(thoth.SourceAgentToolCall) != "agent_tool_call" {
		t.Errorf("SourceAgentToolCall = %q, want %q", thoth.SourceAgentToolCall, "agent_tool_call")
	}
	if string(thoth.SourceAgentLLM) != "agent_llm_invocation" {
		t.Errorf("SourceAgentLLM = %q, want %q", thoth.SourceAgentLLM, "agent_llm_invocation")
	}
}

func TestEventTypeConstants(t *testing.T) {
	t.Parallel()
	cases := map[thoth.EventType]string{
		thoth.EventToolCallPre:   "TOOL_CALL_PRE",
		thoth.EventToolCallPost:  "TOOL_CALL_POST",
		thoth.EventToolCallBlock: "TOOL_CALL_BLOCK",
		thoth.EventLLMInvocation: "LLM_INVOCATION",
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
		thoth.DecisionModify:  "MODIFY",
		thoth.DecisionDefer:   "DEFER",
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
	ev := thoth.NewBehavioralEvent(thoth.BehavioralEventInput{
		AgentID:    "agent-1",
		TenantID:   "tenant-1",
		SessionID:  "sess-1",
		UserID:     "user-1",
		SourceType: thoth.SourceAgentToolCall,
		EventType:  thoth.EventToolCallPre,
		ToolName:   "read_file",
		Content:    "tool invocation requested",
	})
	if ev.TTL == 0 {
		t.Fatal("TTL must not be zero")
	}
	approxExpiry := time.Now().Add(90 * 24 * time.Hour).Unix()
	diff := ev.TTL - approxExpiry
	if diff < -5 || diff > 5 {
		t.Errorf("TTL diff from 90d = %v, expected near zero", diff)
	}
}

func TestBehavioralEventFields(t *testing.T) {
	t.Parallel()
	ev := thoth.NewBehavioralEvent(thoth.BehavioralEventInput{
		AgentID:         "agent-1",
		TenantID:        "tenant-1",
		SessionID:       "sess-1",
		UserID:          "user-1",
		SourceType:      thoth.SourceAgentToolCall,
		EventType:       thoth.EventToolCallPost,
		ToolName:        "write_slack",
		Content:         "tool invocation completed",
		Metadata:        map[string]any{"k": "v"},
		ApprovedScope:   []string{"write_slack"},
		EnforcementMode: thoth.Progressive,
		SessionToolCalls: []string{
			"write_slack",
		},
	})
	if ev.AgentID != "agent-1" {
		t.Errorf("AgentID = %q", ev.AgentID)
	}
	if ev.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q", ev.TenantID)
	}
	if ev.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", ev.SessionID)
	}
	if ev.UserID != "user-1" {
		t.Errorf("UserID = %q", ev.UserID)
	}
	if ev.SourceType != thoth.SourceAgentToolCall {
		t.Errorf("SourceType = %q", ev.SourceType)
	}
	if ev.EventType != thoth.EventToolCallPost {
		t.Errorf("EventType = %q", ev.EventType)
	}
	if ev.ToolName != "write_slack" {
		t.Errorf("ToolName = %q", ev.ToolName)
	}
	if ev.EventID == "" {
		t.Error("EventID must be set")
	}
	if got, wantPrefix := ev.EventID, "tenant-1:"; len(got) <= len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("EventID = %q, want tenant-scoped prefix %q", ev.EventID, wantPrefix)
	}
	if ev.OccurredAt.IsZero() {
		t.Error("OccurredAt must be set")
	}
	if ev.Content == "" {
		t.Error("Content must be set")
	}
	if ev.Metadata == nil {
		t.Error("Metadata must be initialized")
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

func TestThothConfigDefaults_UsesAPIURLAsEnforcerURL(t *testing.T) {
	t.Parallel()
	cfg := thoth.Config{
		AgentID:  "test-agent",
		TenantID: "test-tenant",
		APIURL:   "https://enforce.test.atensecurity.com",
	}
	cfg = thoth.ApplyConfigDefaults(cfg)
	if cfg.EnforcerURL != cfg.APIURL {
		t.Errorf("EnforcerURL = %q, want %q", cfg.EnforcerURL, cfg.APIURL)
	}
}
