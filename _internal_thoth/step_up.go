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

// holdStatusResponse models both the canonical HoldToken polling shape and
// legacy direct decision payloads for backward compatibility.
type holdStatusResponse struct {
	Decision   DecisionType `json:"decision,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Resolved   bool         `json:"resolved"`
	Resolution DecisionType `json:"resolution,omitempty"`
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

	var hold holdStatusResponse
	if err = json.NewDecoder(resp.Body).Decode(&hold); err != nil {
		log.Printf("thoth: warn: step-up poll decode: %v", err)
		return EnforcementDecision{}, false
	}

	// Backward compatibility: support direct decision-shaped payloads.
	switch hold.Decision {
	case DecisionAllow, DecisionBlock, DecisionType("DENY"):
		direct := hold.Decision
		if direct == DecisionType("DENY") {
			direct = DecisionBlock
		}
		return EnforcementDecision{
			Decision: direct,
			Reason:   hold.Reason,
		}, true
	case DecisionStepUp, "":
		// Continue with hold-token parsing below.
	default:
		log.Printf("thoth: warn: step-up poll returned unsupported decision %q", hold.Decision)
		return EnforcementDecision{}, false
	}

	if hold.Resolved {
		switch hold.Resolution {
		case DecisionAllow, DecisionBlock, DecisionType("DENY"):
			resolution := hold.Resolution
			if resolution == DecisionType("DENY") {
				resolution = DecisionBlock
			}
			return EnforcementDecision{
				Decision: resolution,
				Reason:   hold.Reason,
			}, true
		default:
			log.Printf("thoth: warn: step-up poll resolved without valid resolution (got %q)", hold.Resolution)
			return EnforcementDecision{}, false
		}
	}

	return EnforcementDecision{}, false
}
