package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultEnforcerTimeout = 5 * time.Second

type enforcerRequest struct {
	RequestID            string          `json:"request_id"`
	AgentID              string          `json:"agent_id"`
	TenantID             string          `json:"tenant_id"`
	ToolName             string          `json:"tool_name"`
	SessionID            string          `json:"session_id"`
	UserID               string          `json:"user_id"`
	IdentityBinding      map[string]any  `json:"identity_binding,omitempty"`
	ApprovedScope        []string        `json:"approved_scope"`
	SessionToolCalls     []string        `json:"session_tool_calls"`
	ToolArgs             map[string]any  `json:"tool_args,omitempty"`
	EnforcementMode      EnforcementMode `json:"enforcement_mode"`
	Environment          string          `json:"environment"`
	TraceID              string          `json:"enforcement_trace_id,omitempty"`
	ActionAttestationID  string          `json:"action_attestation_id,omitempty"`
	OccurredAt           time.Time       `json:"occurred_at"`
	SessionIntent        string          `json:"session_intent,omitempty"`
	Purpose              string          `json:"purpose,omitempty"`
	DataClassification   string          `json:"data_classification,omitempty"`
	TaskContext          map[string]any  `json:"task_context,omitempty"`
	ModelName            string          `json:"model_name,omitempty"`
	ModelProvider        string          `json:"model_provider,omitempty"`
	ModelArtifactID      string          `json:"model_artifact_id,omitempty"`
	ModelArtifactVersion string          `json:"model_artifact_version,omitempty"`
	AuthContext          map[string]any  `json:"auth_context,omitempty"`
	DelegationContext    map[string]any  `json:"delegation_context,omitempty"`
	Metadata             map[string]any  `json:"metadata,omitempty"`
	// Model usage reported with ReportUsage, sent once (usage.go).
	PromptTokens     *int64   `json:"prompt_tokens,omitempty"`
	CompletionTokens *int64   `json:"completion_tokens,omitempty"`
	EstimatedCostUSD *float64 `json:"estimated_cost_usd,omitempty"`
	// ClientFindings is what the local scan found in the raw arguments (data
	// handling withholding them). Never values.
	ClientFindings *ClientFindings `json:"client_findings,omitempty"`
	// DataHandling declares what this client withheld before sending.
	DataHandling map[string]any `json:"data_handling,omitempty"`
}

// EnforcerClient calls the Thoth enforcement service to obtain a pre-execution decision.
type EnforcerClient struct {
	baseURL  string
	apiKey   string
	failOpen bool
	http     *http.Client
	// dataHandling is nil unless the client withholds values at the source.
	dataHandling *DataHandling
	// usage is the model usage waiting to ride on the next request.
	usage pendingUsage
}

// WithDataHandling sets the source-side data handling applied to every request.
// Call it before the client is shared.
func (c *EnforcerClient) WithDataHandling(dh *DataHandling) *EnforcerClient {
	c.dataHandling = dh
	return c
}

// applyDataHandling scans the raw arguments, then withholds the values and
// declares it. It runs last, so nothing added to the request earlier reaches
// the wire untransformed.
func (c *EnforcerClient) applyDataHandling(req *enforcerRequest) {
	dh := c.dataHandling
	if dh == nil {
		return
	}
	if dh.ScansLocally() {
		// Only counts, categories, hostnames and recipient domains are reported;
		// a check that cannot finish is left out so Thoth sees it as missing.
		if scanner := LoadScanner(); scanner != nil {
			var raw any = req.ToolArgs
			if req.ToolArgs == nil {
				raw = map[string]any{}
			}
			req.ClientFindings = scanner.ClientFindings(req.ToolName, raw, req.Metadata)
		}
	}
	if dh.ToolArguments != "" && req.ToolArgs != nil {
		if keep, next := TransformArguments(req.ToolArgs, dh.ToolArguments, dh.Salt); keep {
			req.ToolArgs, _ = next.(map[string]any)
		} else {
			req.ToolArgs = nil
		}
	}
	if dh.Prompts != "" {
		req.IdentityBinding = dh.transformContextField(req.IdentityBinding)
		req.TaskContext = dh.transformContextField(req.TaskContext)
		req.AuthContext = dh.transformContextField(req.AuthContext)
		req.DelegationContext = dh.transformContextField(req.DelegationContext)
		req.Metadata = dh.transformContextField(req.Metadata)
	}
	req.DataHandling = dh.Declaration()
}

// NewEnforcerClient creates an EnforcerClient with a 5-second HTTP timeout.
func NewEnforcerClient(baseURL, apiKey string, failOpen bool) *EnforcerClient {
	return &EnforcerClient{
		baseURL:  baseURL,
		apiKey:   apiKey,
		failOpen: failOpen,
		http:     &http.Client{Timeout: defaultEnforcerTimeout},
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

var failOpenDecision = EnforcementDecision{
	Decision: DecisionAllow,
	Reason:   "enforcer unavailable (fail-open)",
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
	actionAttestationID := strings.TrimSpace(check.ActionAttestationID)
	if actionAttestationID == "" {
		actionAttestationID = uuid.NewString()
	}

	reqBody := enforcerRequest{
		RequestID:            uuid.New().String(),
		AgentID:              check.AgentID,
		TenantID:             check.TenantID,
		ToolName:             check.ToolName,
		SessionID:            check.SessionID,
		UserID:               check.UserID,
		IdentityBinding:      check.IdentityBinding,
		ApprovedScope:        approvedScope,
		SessionToolCalls:     sessionToolCalls,
		ToolArgs:             check.ToolArgs,
		EnforcementMode:      check.EnforcementMode,
		Environment:          check.Environment,
		TraceID:              check.EnforcementTraceID,
		ActionAttestationID:  actionAttestationID,
		OccurredAt:           time.Now().UTC(),
		SessionIntent:        check.SessionIntent,
		Purpose:              check.Purpose,
		DataClassification:   check.DataClassification,
		TaskContext:          check.TaskContext,
		ModelName:            check.ModelName,
		ModelProvider:        check.ModelProvider,
		ModelArtifactID:      check.ModelArtifactID,
		ModelArtifactVersion: check.ModelArtifactVersion,
		AuthContext:          check.AuthContext,
		DelegationContext:    check.DelegationContext,
		Metadata:             check.RequestMetadata,
	}
	if runtimeIdentity := strings.TrimSpace(check.MCPRuntimeIdentity); runtimeIdentity != "" {
		if reqBody.Metadata == nil {
			reqBody.Metadata = map[string]any{}
		}
		if _, exists := reqBody.Metadata["mcp_runtime_identity"]; !exists {
			reqBody.Metadata["mcp_runtime_identity"] = runtimeIdentity
		}
		if reqBody.AuthContext == nil {
			reqBody.AuthContext = map[string]any{}
		}
		if _, exists := reqBody.AuthContext["service_identity"]; !exists {
			reqBody.AuthContext["service_identity"] = runtimeIdentity
		}
	}
	usage := c.usage.take()
	if usage != nil {
		if usage.PromptTokens > 0 {
			reqBody.PromptTokens = &usage.PromptTokens
		}
		if usage.CompletionTokens > 0 {
			reqBody.CompletionTokens = &usage.CompletionTokens
		}
		reqBody.EstimatedCostUSD = usage.CostUSD
	}
	c.applyDataHandling(&reqBody)
	buf, err := json.Marshal(reqBody)
	if err != nil {
		// Never sent: its usage goes with the next call. Class only, no arguments in logs.
		c.restoreUsage(usage)
		log.Printf("thoth: ERROR: request could not be built (%T), blocked locally", err)
		return requestNotBuiltDecision(), fmt.Errorf("thoth: enforcer marshal: %w", err)
	}

	// A body over the enforcer's limit is refused here and never sent: the server answers 413
	// but may reset the connection while we are still uploading, which would look like a
	// transport failure, and fail-open treats that as allow.
	if len(buf) > MaxRequestBytes {
		log.Printf("thoth: ERROR: request of %d bytes is over the %d-byte enforcer limit, blocked locally", len(buf), MaxRequestBytes)
		c.restoreUsage(usage)
		return requestTooLargeDecision(), ErrRequestTooLarge
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/enforce", bytes.NewReader(buf))
	if err != nil {
		c.restoreUsage(usage)
		return requestNotBuiltDecision(), fmt.Errorf("thoth: enforcer request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("X-Api-Key", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// The server did not see this call: its usage goes with the next one.
		c.restoreUsage(usage)
		if c.failOpen {
			log.Printf("thoth: WARN: enforcer unreachable, fail-open fallback to ALLOW: %v", err)
			return failOpenDecision, nil
		}
		log.Printf("thoth: ERROR: enforcer unreachable, fail-closed fallback to BLOCK: %v", err)
		return fallbackDecision, fmt.Errorf("thoth: enforcer request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			c.restoreUsage(usage)
		}
		if c.failOpen && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError) {
			log.Printf(
				"thoth: WARN: enforcer returned retryable status %d, fail-open fallback to ALLOW",
				resp.StatusCode,
			)
			return EnforcementDecision{
				Decision: DecisionAllow,
				Reason:   fmt.Sprintf("enforcer unavailable (status=%d, fail-open)", resp.StatusCode),
			}, nil
		}
		err = fmt.Errorf("thoth: enforcer returned HTTP %d", resp.StatusCode)
		log.Printf("thoth: ERROR: %v, fail-closed fallback to BLOCK", err)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return EnforcementDecision{
				Decision: DecisionBlock,
				Reason:   fmt.Sprintf("enforcer unavailable (status=%d)", resp.StatusCode),
			}, err
		}
		return EnforcementDecision{
			Decision: DecisionBlock,
			Reason:   fmt.Sprintf("enforcer rejected request (status=%d)", resp.StatusCode),
		}, err
	}

	// A failure while reading the body (stall, reset, short read) is a network failure:
	// treat it like any transport error. A body read in full that cannot be decoded is not.
	// The read is bounded: a reply over the limit is a contract failure, never an allow.
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if readErr == nil && int64(len(raw)) > maxResponseBytes {
		log.Printf("thoth: ERROR: enforcer response over the %d-byte limit (status=%d), blocked in both modes", maxResponseBytes, resp.StatusCode)
		return EnforcementDecision{
			Decision: DecisionBlock,
			Reason:   "enforcer response not understood",
		}, fmt.Errorf("thoth: enforcer response not understood (HTTP %d, over size limit)", resp.StatusCode)
	}
	if readErr != nil {
		// Usage is put back even though a stalled reply may mean the server already
		// counted the call (inferred, not verified): we fail toward not losing usage,
		// at the risk of counting one call twice.
		c.restoreUsage(usage)
		if c.failOpen {
			log.Printf("thoth: WARN: enforcer response read failed, fail-open fallback to ALLOW: %v", readErr)
			return failOpenDecision, nil
		}
		log.Printf("thoth: ERROR: enforcer response read failed, fail-closed fallback to BLOCK: %v", readErr)
		return fallbackDecision, fmt.Errorf("thoth: enforcer response read: %w", readErr)
	}

	var dec EnforcementDecision
	decodeErr := decodeSingleJSON(raw, &dec)
	if decodeErr != nil {
		// The enforcer answered, so this is not an outage: fail-open does not apply.
		// Log the error class and status only, never the response body. The server saw
		// the call, so its usage is not restored (as for a 4xx).
		log.Printf("thoth: ERROR: enforcer response not understood (status=%d, %T), blocked in both modes", resp.StatusCode, decodeErr)
		return EnforcementDecision{
			Decision: DecisionBlock,
			Reason:   "enforcer response not understood",
		}, fmt.Errorf("thoth: enforcer response not understood (HTTP %d)", resp.StatusCode)
	}
	if dec.ActionAttestationID == "" {
		dec.ActionAttestationID = actionAttestationID
	}
	normalizeEnforcementDecision(&dec)
	return dec, nil
}

// decodeSingleJSON decodes exactly one JSON object: trailing data and null are refused.
func decodeSingleJSON(raw []byte, dst *EnforcementDecision) error {
	if string(bytes.TrimSpace(raw)) == "null" {
		return errors.New("null body")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func requestNotBuiltDecision() EnforcementDecision {
	return EnforcementDecision{Decision: DecisionBlock, Reason: "request could not be built"}
}

func (c *EnforcerClient) restoreUsage(u *Usage) {
	if u != nil {
		c.usage.add(*u)
	}
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

	// The enforcer carries an argument modification as decision=ALLOW next to
	// authorization_decision=MODIFY. Routing on decision alone would run the tool
	// with its original arguments, so a MODIFY beside an ALLOW is a MODIFY. A
	// stricter routing decision (BLOCK, STEP_UP, DEFER) is never relaxed.
	if dec.Decision == DecisionAllow {
		switch strings.ToUpper(strings.TrimSpace(dec.AuthorizationDecision)) {
		case "MODIFY", "MODIFIED", "TRANSFORM":
			dec.Decision = DecisionModify
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

// MaxRequestBytes is the enforcer's default request limit.
// DefaultMaxResponseBytes caps how much of an enforcer reply the SDK reads (16 MiB).
const DefaultMaxResponseBytes int64 = 16 * 1024 * 1024

// maxResponseBytes is a variable so tests can lower it.
var maxResponseBytes = DefaultMaxResponseBytes

const MaxRequestBytes = 4 * 1024 * 1024

// ErrRequestTooLarge reports a request refused locally for its size (reason code
// enforcer_request_too_large).
var ErrRequestTooLarge = errors.New("thoth: enforcer_request_too_large: the request is larger than the enforcer accepts")

func requestTooLargeDecision() EnforcementDecision {
	d := fallbackDecision
	d.Reason = "enforcer_request_too_large: the request is larger than the enforcer accepts, so the action is not allowed; use smaller tool arguments or ask a reviewer for a held action"
	return d
}
