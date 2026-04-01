package thoth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const defaultPollInterval = 5 * time.Second

var blockTimeout = EnforcementDecision{
	Decision: DecisionBlock,
	Reason:   "step-up auth timeout",
}

// StepUpClient polls the enforcement service for a step-up authentication decision.
type StepUpClient struct {
	baseURL      string
	apiKey       string
	pollInterval time.Duration
	http         *http.Client
}

// NewStepUpClient creates a StepUpClient. If pollInterval is zero, it defaults to 5s.
func NewStepUpClient(baseURL, apiKey string, pollInterval time.Duration) *StepUpClient {
	if pollInterval == 0 {
		pollInterval = defaultPollInterval
	}
	return &StepUpClient{
		baseURL:      baseURL,
		apiKey:       apiKey,
		pollInterval: pollInterval,
		http:         &http.Client{Timeout: defaultEnforcerTimeout},
	}
}

// PollInterval returns the configured polling interval.
func (c *StepUpClient) PollInterval() time.Duration {
	return c.pollInterval
}

// Wait polls the enforcer for approval of holdToken until the context deadline is exceeded.
func (c *StepUpClient) Wait(ctx context.Context, holdToken string) EnforcementDecision {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	for {
		if dec, ok := c.poll(ctx, holdToken); ok {
			return dec
		}
		select {
		case <-ctx.Done():
			return blockTimeout
		case <-ticker.C:
		}
	}
}

func (c *StepUpClient) poll(ctx context.Context, holdToken string) (EnforcementDecision, bool) {
	url := fmt.Sprintf("%s/v1/enforce/hold/%s", c.baseURL, holdToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("thoth: warn: step-up poll request build: %v", err)
		return EnforcementDecision{}, false
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return blockTimeout, true
		}
		log.Printf("thoth: warn: step-up poll error: %v", err)
		return EnforcementDecision{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return EnforcementDecision{}, false
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("thoth: warn: step-up poll returned HTTP %d", resp.StatusCode)
		return EnforcementDecision{}, false
	}

	var dec EnforcementDecision
	if err = json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		log.Printf("thoth: warn: step-up poll decode: %v", err)
		return EnforcementDecision{}, false
	}
	if dec.Decision != DecisionStepUp {
		return dec, true
	}
	return EnforcementDecision{}, false
}
