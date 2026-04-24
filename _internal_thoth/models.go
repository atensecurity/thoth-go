// Package thoth provides a Go SDK for wrapping AI agent tools with Thoth governance.
// It instruments tool calls with pre-enforcement checks and post-execution event emission.
package thoth

import (
	"strings"
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
	SourceAgentToolCall SourceType = "agent_tool_call"
	SourceAgentLLM      SourceType = "agent_llm_invocation"
)

// EventType classifies behavioral events.
type EventType string

const (
	EventToolCallPre   EventType = "TOOL_CALL_PRE"
	EventToolCallPost  EventType = "TOOL_CALL_POST"
	EventToolCallBlock EventType = "TOOL_CALL_BLOCK"
	EventLLMInvocation EventType = "LLM_INVOCATION"
)

// DecisionType is the outcome returned by the enforcer.
type DecisionType string

const (
	DecisionAllow   DecisionType = "ALLOW"
	DecisionBlock   DecisionType = "BLOCK"
	DecisionStepUp  DecisionType = "STEP_UP"
	DecisionModify  DecisionType = "MODIFY"
	DecisionDefer   DecisionType = "DEFER"
	DecisionObserve DecisionType = "observe"
)

// ttlDays is the default TTL for behavioral events (90 days).
const ttlDays = 90

// BehavioralEventInput is the canonical SDK payload for behavioral telemetry.
// It matches the enforcer/eventingestor contract and avoids legacy-only fields.
type BehavioralEventInput struct {
	AgentID          string
	TenantID         string
	SessionID        string
	UserID           string
	SourceType       SourceType
	EventType        EventType
	ToolName         string
	Content          string
	Metadata         map[string]any
	ApprovedScope    []string
	EnforcementMode  EnforcementMode
	SessionToolCalls []string
	OccurredAt       time.Time
	ViolationID      string
}

// BehavioralEvent represents a single observable action by the agent.
type BehavioralEvent struct {
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

// NewBehavioralEvent constructs a BehavioralEvent with a generated ID, current timestamp,
// and a TTL set to 90 days from now.
func NewBehavioralEvent(input BehavioralEventInput) BehavioralEvent {
	occurredAt := input.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	if input.SourceType == "" {
		input.SourceType = SourceAgentToolCall
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}
	if input.ApprovedScope == nil {
		input.ApprovedScope = []string{}
	}
	if input.SessionToolCalls == nil {
		input.SessionToolCalls = []string{}
	}
	return BehavioralEvent{
		EventID:          uuid.New().String(),
		TenantID:         input.TenantID,
		AgentID:          input.AgentID,
		SessionID:        input.SessionID,
		UserID:           input.UserID,
		SourceType:       input.SourceType,
		EventType:        input.EventType,
		ToolName:         input.ToolName,
		Content:          ensureContent(input.Content, input.EventType, input.ToolName),
		Metadata:         input.Metadata,
		ApprovedScope:    input.ApprovedScope,
		EnforcementMode:  input.EnforcementMode,
		SessionToolCalls: input.SessionToolCalls,
		OccurredAt:       occurredAt,
		TTL:              occurredAt.Add(ttlDays * 24 * time.Hour).Unix(),
		ViolationID:      input.ViolationID,
	}
}

func ensureContent(content string, eventType EventType, toolName string) string {
	if strings.TrimSpace(content) != "" {
		return content
	}
	switch eventType {
	case EventToolCallPre:
		return "tool invocation requested"
	case EventToolCallPost:
		return "tool invocation completed"
	case EventToolCallBlock:
		return "tool invocation blocked"
	case EventLLMInvocation:
		return "llm invocation telemetry"
	default:
		return "behavioral event"
	}
}

// EnforcementDecision is the response from the enforcer service.
type EnforcementDecision struct {
	Decision              DecisionType   `json:"decision"`
	AuthorizationDecision string         `json:"authorization_decision,omitempty"`
	DecisionReasonCode    string         `json:"decision_reason_code,omitempty"`
	ActionClassification  string         `json:"action_classification,omitempty"`
	Reason                string         `json:"reason,omitempty"`
	ViolationID           string         `json:"violation_id,omitempty"`
	HoldToken             string         `json:"hold_token,omitempty"`
	RiskScore             float64        `json:"risk_score,omitempty"`
	LatencyMs             float64        `json:"latency_ms,omitempty"`
	Receipt               map[string]any `json:"receipt,omitempty"`
	ModifiedToolArgs      map[string]any `json:"modified_tool_args,omitempty"`
	ModificationReason    string         `json:"modification_reason,omitempty"`
	DeferReason           string         `json:"defer_reason,omitempty"`
	DeferTimeoutSeconds   int            `json:"defer_timeout_seconds,omitempty"`
	StepUpTimeoutSeconds  int            `json:"step_up_timeout_seconds,omitempty"`
}

// CheckRequest contains all fields needed by the enforcer to produce a policy decision.
type CheckRequest struct {
	ToolName  string
	SessionID string
	AgentID   string
	TenantID  string
	UserID    string
	// IdentityBinding carries actor/tenant/user identity attributes used
	// for pre-execution binding checks.
	IdentityBinding  map[string]any
	ApprovedScope    []string
	EnforcementMode  EnforcementMode
	SessionToolCalls []string
	// ToolArgs is the normalized tool payload sent to the enforcer for
	// policy evaluation.
	ToolArgs map[string]any
	// Environment scopes policy lookup (for example, dev vs prod).
	Environment string
	// EnforcementTraceID correlates a tool call through enforcement and
	// downstream policy engines.
	EnforcementTraceID string
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
	// IdentityBinding carries actor/tenant/user identity attributes used
	// for pre-execution binding checks.
	IdentityBinding map[string]any
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
	// Environment scopes policy lookup (for example, dev vs prod).
	// Defaults to "prod".
	Environment string
	// EnforcementTraceID correlates requests through enforcement and downstream
	// policy engines. Defaults to the session ID when empty.
	EnforcementTraceID string
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
	if cfg.Environment == "" {
		cfg.Environment = "prod"
	}
	if cfg.ApprovedScope == nil {
		cfg.ApprovedScope = []string{}
	}
	return cfg
}
