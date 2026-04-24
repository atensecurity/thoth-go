package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultEnforcerTimeout = 5 * time.Second

type enforcerRequest struct {
	RequestID        string          `json:"request_id"`
	AgentID          string          `json:"agent_id"`
	TenantID         string          `json:"tenant_id"`
	ToolName         string          `json:"tool_name"`
	SessionID        string          `json:"session_id"`
	UserID           string          `json:"user_id"`
	IdentityBinding  map[string]any  `json:"identity_binding,omitempty"`
	ApprovedScope    []string        `json:"approved_scope"`
	SessionToolCalls []string        `json:"session_tool_calls"`
	ToolArgs         map[string]any  `json:"tool_args,omitempty"`
	EnforcementMode  EnforcementMode `json:"enforcement_mode"`
	Environment      string          `json:"environment"`
	TraceID          string          `json:"enforcement_trace_id,omitempty"`
	OccurredAt       time.Time       `json:"occurred_at"`
	SessionIntent    string          `json:"session_intent,omitempty"`
}

// EnforcerClient calls the Thoth enforcement service to obtain a pre-execution decision.
type EnforcerClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewEnforcerClient creates an EnforcerClient with a 5-second HTTP timeout.
func NewEnforcerClient(baseURL, apiKey string) *EnforcerClient {
	return &EnforcerClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: defaultEnforcerTimeout},
	}
}

// Timeout returns the configured HTTP client timeout.
func (c *EnforcerClient) Timeout() time.Duration {
	return c.http.Timeout
}

var fallbackDecision = EnforcementDecision{
	Decision: DecisionBlock,
	Reason:   "enforcer unavailable",
}

// Check sends a CheckRequest to the enforcer and returns its decision.
func (c *EnforcerClient) Check(ctx context.Context, check CheckRequest) (EnforcementDecision, error) {
	approvedScope := check.ApprovedScope
	if approvedScope == nil {
		approvedScope = []string{}
	}
	sessionToolCalls := check.SessionToolCalls
	if sessionToolCalls == nil {
		sessionToolCalls = []string{}
	}

	reqBody := enforcerRequest{
		RequestID:        uuid.New().String(),
		AgentID:          check.AgentID,
		TenantID:         check.TenantID,
		ToolName:         check.ToolName,
		SessionID:        check.SessionID,
		UserID:           check.UserID,
		IdentityBinding:  check.IdentityBinding,
		ApprovedScope:    approvedScope,
		SessionToolCalls: sessionToolCalls,
		ToolArgs:         check.ToolArgs,
		EnforcementMode:  check.EnforcementMode,
		Environment:      check.Environment,
		TraceID:          check.EnforcementTraceID,
		OccurredAt:       time.Now().UTC(),
		SessionIntent:    check.SessionIntent,
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return fallbackDecision, fmt.Errorf("thoth: enforcer marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/enforce", bytes.NewReader(buf))
	if err != nil {
		return fallbackDecision, fmt.Errorf("thoth: enforcer request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("thoth: warn: enforcer unreachable, defaulting to BLOCK: %v", err)
		return fallbackDecision, fmt.Errorf("thoth: enforcer request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("thoth: enforcer returned HTTP %d", resp.StatusCode)
		log.Printf("thoth: warn: %v, defaulting to BLOCK", err)
		return fallbackDecision, err
	}

	var dec EnforcementDecision
	if decodeErr := json.NewDecoder(resp.Body).Decode(&dec); decodeErr != nil {
		err = fmt.Errorf("thoth: enforcer decode: %w", decodeErr)
		log.Printf("thoth: warn: %v, defaulting to BLOCK", err)
		return fallbackDecision, err
	}
	normalizeEnforcementDecision(&dec)
	return dec, nil
}

func normalizeEnforcementDecision(dec *EnforcementDecision) {
	if dec == nil {
		return
	}

	raw := strings.TrimSpace(string(dec.Decision))
	if raw == "" {
		raw = strings.TrimSpace(dec.AuthorizationDecision)
	}

	switch strings.ToUpper(raw) {
	case "ALLOW":
		dec.Decision = DecisionAllow
	case "BLOCK", "DENY":
		dec.Decision = DecisionBlock
	case "STEP_UP", "CHALLENGE", "ESCALATE", "REVIEW":
		dec.Decision = DecisionStepUp
	case "MODIFY", "MODIFIED", "TRANSFORM":
		dec.Decision = DecisionModify
	case "DEFER", "DEFERRED", "HOLD":
		dec.Decision = DecisionDefer
	default:
		dec.Decision = DecisionBlock
		if dec.Reason == "" {
			dec.Reason = "unsupported authorization decision"
		}
	}

	if dec.Reason == "" {
		switch dec.Decision {
		case DecisionModify:
			dec.Reason = dec.ModificationReason
		case DecisionDefer:
			dec.Reason = dec.DeferReason
		}
	}
}
