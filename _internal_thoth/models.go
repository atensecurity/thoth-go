// Package thoth provides a Go SDK for wrapping AI agent tools with Thoth governance.
// It instruments tool calls with pre-enforcement checks and post-execution event emission.
package thoth

import (
	"time"

	"github.com/google/uuid"
)

// EnforcementMode controls how Thoth responds to policy violations.
type EnforcementMode string

const (
	// Observe logs the violation but never blocks.
	Observe EnforcementMode = "observe"
	// StepUp pauses execution and requires step-up authentication before proceeding.
	StepUp EnforcementMode = "step_up"
	// Block immediately returns a PolicyViolationError on any violation.
	Block EnforcementMode = "block"
	// Progressive escalates: first violation → step-up, subsequent → block.
	Progressive EnforcementMode = "progressive"
)

// SourceType identifies who originated the action.
type SourceType string

const (
	SourceAgent SourceType = "agent"
	SourceHuman SourceType = "human"
)

// EventType classifies behavioral events.
type EventType string

const (
	EventToolCall   EventType = "tool_call"
	EventTokenSpend EventType = "token_spend"
	EventScopeCheck EventType = "scope_check"
)

// DecisionType is the outcome returned by the enforcer.
type DecisionType string

const (
	DecisionAllow   DecisionType = "ALLOW"
	DecisionBlock   DecisionType = "BLOCK"
	DecisionStepUp  DecisionType = "STEP_UP"
	DecisionObserve DecisionType = "observe"
)

// ttlDays is the default TTL for behavioral events (90 days).
const ttlDays = 90

// BehavioralEvent represents a single observable action by the agent.
type BehavioralEvent struct {
	EventID   string            `json:"event_id"`
	AgentID   string            `json:"agent_id"`
	TenantID  string            `json:"tenant_id"`
	SessionID string            `json:"session_id"`
	EventType EventType         `json:"event_type"`
	ToolName  string            `json:"tool_name,omitempty"`
	Source    SourceType        `json:"source"`
	Tokens    int64             `json:"tokens,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	TTL       time.Time         `json:"ttl"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// NewBehavioralEvent constructs a BehavioralEvent with a generated ID, current timestamp,
// and a TTL set to 90 days from now.
func NewBehavioralEvent(agentID, tenantID, sessionID string, eventType EventType, toolName string) BehavioralEvent {
	now := time.Now().UTC()
	return BehavioralEvent{
		EventID:   uuid.New().String(),
		AgentID:   agentID,
		TenantID:  tenantID,
		SessionID: sessionID,
		EventType: eventType,
		ToolName:  toolName,
		Source:    SourceAgent,
		Timestamp: now,
		TTL:       now.Add(ttlDays * 24 * time.Hour),
	}
}

// EnforcementDecision is the response from the enforcer service.
type EnforcementDecision struct {
	Decision    DecisionType `json:"decision"`
	Reason      string       `json:"reason,omitempty"`
	ViolationID string       `json:"violation_id,omitempty"`
	HoldToken   string       `json:"hold_token,omitempty"`
	RiskScore   float64      `json:"risk_score,omitempty"`
	LatencyMs   float64      `json:"latency_ms,omitempty"`
}

// CheckRequest contains all fields needed by the enforcer to produce a policy decision.
type CheckRequest struct {
	ToolName         string
	SessionID        string
	AgentID          string
	TenantID         string
	UserID           string
	ApprovedScope    []string
	EnforcementMode  EnforcementMode
	SessionToolCalls []string
	// SessionIntent declares the purpose of the session for HIPAA minimum-necessary
	// enforcement. When a compliance pack defines session_scopes, tools outside the
	// declared intent scope are step-up-challenged. Empty string means no intent check.
	SessionIntent string
}

// Emitter is the interface for behavioral event emission backends.
type Emitter interface {
	Emit(event *BehavioralEvent)
	Close()
}

// Config holds the configuration for a Thoth-instrumented agent.
type Config struct {
	// AgentID is the unique identifier for this agent instance.
	AgentID string
	// TenantID is the customer tenant this agent operates under.
	TenantID string
	// UserID identifies the user on whose behalf the agent is acting.
	UserID string
	// ApprovedScope lists the tool names this agent is authorized to call.
	ApprovedScope []string
	// Enforcement controls the response mode on policy violations.
	Enforcement EnforcementMode
	// EnforcerURL is the base URL of the enforcement service.
	// Defaults to APIURL when provided, otherwise "http://enforcer:8080".
	EnforcerURL string
	// APIKey is the Thoth API key for hosted authentication.
	APIKey string
	// APIURL is the unified tenant API base URL used for hosted event emission and,
	// when EnforcerURL is omitted, enforcement checks.
	APIURL string
	// SessionIntent declares the purpose of this session for HIPAA minimum-necessary
	// enforcement. Passed on every enforce call. Empty string means no intent check.
	SessionIntent string
}

// ApplyConfigDefaults fills in zero-value fields with sensible defaults.
func ApplyConfigDefaults(cfg Config) Config {
	if cfg.EnforcerURL == "" {
		if cfg.APIURL != "" {
			cfg.EnforcerURL = cfg.APIURL
		} else {
			cfg.EnforcerURL = "http://enforcer:8080"
		}
	}
	if cfg.Enforcement == "" {
		cfg.Enforcement = Progressive
	}
	return cfg
}
