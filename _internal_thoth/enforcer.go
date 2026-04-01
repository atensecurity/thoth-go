package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	ApprovedScope    []string        `json:"approved_scope"`
	SessionToolCalls []string        `json:"session_tool_calls"`
	EnforcementMode  EnforcementMode `json:"enforcement_mode"`
	OccurredAt       time.Time       `json:"occurred_at"`
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

var allowDecision = EnforcementDecision{Decision: DecisionAllow}

// Check sends a CheckRequest to the enforcer and returns its decision.
func (c *EnforcerClient) Check(ctx context.Context, check CheckRequest) (EnforcementDecision, error) {
	reqBody := enforcerRequest{
		RequestID:        uuid.New().String(),
		AgentID:          check.AgentID,
		TenantID:         check.TenantID,
		ToolName:         check.ToolName,
		SessionID:        check.SessionID,
		UserID:           check.UserID,
		ApprovedScope:    check.ApprovedScope,
		SessionToolCalls: check.SessionToolCalls,
		EnforcementMode:  check.EnforcementMode,
		OccurredAt:       time.Now().UTC(),
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return allowDecision, fmt.Errorf("thoth: enforcer marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/enforce", bytes.NewReader(buf))
	if err != nil {
		return allowDecision, fmt.Errorf("thoth: enforcer request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("thoth: warn: enforcer unreachable, defaulting to ALLOW: %v", err)
		return allowDecision, fmt.Errorf("thoth: enforcer request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err = fmt.Errorf("thoth: enforcer returned HTTP %d", resp.StatusCode)
		log.Printf("thoth: warn: %v, defaulting to ALLOW", err)
		return allowDecision, err
	}

	var dec EnforcementDecision
	if decodeErr := json.NewDecoder(resp.Body).Decode(&dec); decodeErr != nil {
		err = fmt.Errorf("thoth: enforcer decode: %w", decodeErr)
		log.Printf("thoth: warn: %v, defaulting to ALLOW", err)
		return allowDecision, err
	}
	return dec, nil
}
