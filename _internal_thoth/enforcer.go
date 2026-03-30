package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const defaultEnforcerTimeout = 5 * time.Second

type enforcerRequest struct {
	ToolName  string   `json:"tool_name"`
	SessionID string   `json:"session_id"`
	ToolCalls []string `json:"tool_calls"`
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

// Check sends toolName and session context to the enforcer and returns its decision.
func (c *EnforcerClient) Check(ctx context.Context, toolName, sessionID string, toolCalls []string) (EnforcementDecision, error) {
	reqBody := enforcerRequest{ToolName: toolName, SessionID: sessionID, ToolCalls: toolCalls}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return allowDecision, fmt.Errorf("thoth: enforcer marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/check", bytes.NewReader(buf))
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
