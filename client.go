// Package thoth provides the Aten Thoth SDK for instrumenting Go AI agents
// with governance, policy enforcement, and behavioral monitoring.
//
// Thoth wraps your agent's tool functions with pre-execution policy checks
// (enforcer) and asynchronous behavioral event emission (HTTP). Enforcement is
// fail-closed by default; set FailOpen (or THOTH_FAIL_OPEN=true) to allow tool
// execution when enforcement infrastructure is unavailable.
//
// Quick start:
//
//	client, err := thoth.NewClient(thoth.Config{
//	    APIKey:   os.Getenv("THOTH_API_KEY"),
//	    APIURL:   os.Getenv("THOTH_API_URL"),
//	    TenantID: "your-tenant-id",
//	    AgentID:  "invoice-processor-v2",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	searchDocs := client.WrapTool("search_docs", func(ctx context.Context, query string) (string, error) {
//	    return mySearch(ctx, query)
//	})
//
//	result, err := searchDocs(ctx, "quarterly earnings")
//
// Environment variable fallbacks (lowest priority, overridden by Config fields):
//
//	THOTH_API_KEY    — API key for hosted Thoth authentication
//	THOTH_EVENT_INGEST_TOKEN — optional dedicated token for /v1/events/batch
//	THOTH_TENANT_ID  — tenant identifier
//	THOTH_AGENT_ID   — agent identifier
//	THOTH_API_URL    — unified tenant API base URL override (enforcement + events)
//	THOTH_ENV        — environment scope (default: prod)
//	THOTH_ENVIRONMENT — alternate environment scope key (default: prod)
//	THOTH_ENFORCEMENT_MODE — enforcement mode override (default: block)
//	THOTH_ENFORCEMENT — legacy alias for enforcement mode override
//	THOTH_ENFORCEMENT_TRACE_ID — explicit cross-service trace ID override
//	THOTH_ACTION_ATTESTATION_ID — optional per-action attestation ID override
//	THOTH_USER_ID    — user identifier for policy evaluation
//	THOTH_APPROVED_SCOPE — comma-delimited approved tool names
//	THOTH_SESSION_INTENT — HIPAA minimum-necessary session intent
//	THOTH_PURPOSE — default purpose context for tool calls
//	THOTH_DATA_CLASSIFICATION — default data classification context
//	THOTH_TASK_CONTEXT_JSON — JSON object with initiated_by/task_id/chain
//	THOTH_MODEL_NAME — optional model name context for policy checks
//	THOTH_MODEL_PROVIDER — optional model provider context for policy checks
//	THOTH_MODEL_ARTIFACT_ID — optional model artifact ID for supply-chain gate
//	THOTH_MODEL_ARTIFACT_VERSION — optional model artifact version for supply-chain gate
//	THOTH_AUTH_CONTEXT_JSON — optional JSON auth context propagated to enforcer
//	THOTH_DELEGATION_CONTEXT_JSON — optional JSON delegation context propagated to enforcer
//	THOTH_MCP_RUNTIME_IDENTITY — optional runtime identity propagated for MCP capability checks
//	THOTH_REQUEST_METADATA_JSON — optional JSON metadata merged into enforce payload
//	THOTH_LOG_LEVEL — optional SDK decision-log level override (falls back to LOG_LEVEL)
//	THOTH_FAIL_OPEN — when true, enforcer transport/5xx/429 failures allow tool execution
package thoth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ithoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

const defaultTimeout = 5 * time.Second

// Config holds configuration for the Thoth SDK client.
type Config struct {
	// APIKey is the Thoth API key for hosted authentication.
	// Env fallback: THOTH_API_KEY.
	APIKey string

	// EventIngestToken is an optional dedicated token for event ingestion.
	// When set, SDK sends X-Thoth-Event-Ingest-Token on /v1/events/batch.
	// Env fallback: THOTH_EVENT_INGEST_TOKEN.
	EventIngestToken string

	// TenantID is your organization's Thoth tenant identifier.
	// Env fallback: THOTH_TENANT_ID.
	TenantID string

	// AgentID is the unique name for this agent instance.
	// Env fallback: THOTH_AGENT_ID.
	AgentID string

	// APIURL overrides the Thoth API base URL.
	// Required (directly or via THOTH_API_URL). This single URL is used for
	// both policy enforcement (/v1/enforce) and event ingestion (/v1/events/batch).
	// Env fallback: THOTH_API_URL.
	APIURL string

	// Environment scopes policy lookup (for example, dev vs prod).
	// Defaults to "prod".
	// Env fallback: THOTH_ENV, then THOTH_ENVIRONMENT.
	Environment string

	// UserID identifies the user on whose behalf the agent is acting.
	// Env fallback: THOTH_USER_ID.
	UserID string

	// IdentityBinding carries actor/tenant/user identity attributes used
	// for pre-execution binding checks.
	IdentityBinding map[string]any

	// ApprovedScope lists tool names authorized for this agent.
	// Env fallback: THOTH_APPROVED_SCOPE (comma-delimited).
	ApprovedScope []string

	// SessionIntent declares the workflow purpose for HIPAA minimum-necessary
	// enforcement.
	// Env fallback: THOTH_SESSION_INTENT.
	SessionIntent string

	// Purpose declares the default purpose context for calls emitted by this SDK.
	// Env fallback: THOTH_PURPOSE.
	Purpose string

	// DataClassification declares the default data sensitivity label sent with
	// enforcement requests and telemetry.
	// Env fallback: THOTH_DATA_CLASSIFICATION.
	DataClassification string

	// TaskContext is optional governance attribution context. Expected keys:
	// initiated_by, task_id, chain.
	// Env fallback: THOTH_TASK_CONTEXT_JSON.
	TaskContext map[string]any

	// ModelName is an optional model identifier propagated to policy checks.
	// Env fallback: THOTH_MODEL_NAME.
	ModelName string

	// ModelProvider is an optional model-provider identifier propagated to
	// policy checks.
	// Env fallback: THOTH_MODEL_PROVIDER.
	ModelProvider string

	// ModelArtifactID identifies the active model artifact for deterministic
	// supply-chain activation checks.
	// Env fallback: THOTH_MODEL_ARTIFACT_ID.
	ModelArtifactID string

	// ModelArtifactVersion is the expected version for the active model
	// artifact.
	// Env fallback: THOTH_MODEL_ARTIFACT_VERSION.
	ModelArtifactVersion string

	// AuthContext is optional principal/service identity context used by
	// policy checks.
	// Env fallback: THOTH_AUTH_CONTEXT_JSON.
	AuthContext map[string]any

	// DelegationContext is optional task-delegation context used by policy
	// checks.
	// Env fallback: THOTH_DELEGATION_CONTEXT_JSON.
	DelegationContext map[string]any

	// MCPRuntimeIdentity is an optional runtime identity propagated for MCP
	// capability-scoped checks.
	// Env fallback: THOTH_MCP_RUNTIME_IDENTITY.
	MCPRuntimeIdentity string

	// RequestMetadata is optional metadata merged into each enforcement request.
	// Env fallback: THOTH_REQUEST_METADATA_JSON.
	RequestMetadata map[string]any

	// EnforcementTraceID sets an explicit trace correlation ID for enforcement
	// requests. When empty, session ID is used.
	// Env fallback: THOTH_ENFORCEMENT_TRACE_ID.
	EnforcementTraceID string

	// ActionAttestationID sets an explicit action-attestation correlation ID for
	// enforce requests. When empty, SDK generates one per tool call.
	// Env fallback: THOTH_ACTION_ATTESTATION_ID.
	ActionAttestationID string

	// Timeout is the HTTP timeout for enforcer calls. Default: 5s.
	Timeout time.Duration

	// Enforcement controls how policy violations are handled.
	// Default: "block".
	Enforcement string

	// FailOpen allows tool execution when enforcement infrastructure is
	// unavailable (network error, 429, or 5xx). Auth failures still block.
	// Env fallback: THOTH_FAIL_OPEN.
	FailOpen bool
}

func applyEnvFallbacks(cfg Config) Config {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("THOTH_API_KEY")
	}
	if cfg.EventIngestToken == "" {
		cfg.EventIngestToken = os.Getenv("THOTH_EVENT_INGEST_TOKEN")
	}
	if cfg.TenantID == "" {
		cfg.TenantID = os.Getenv("THOTH_TENANT_ID")
	}
	if cfg.AgentID == "" {
		cfg.AgentID = os.Getenv("THOTH_AGENT_ID")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = os.Getenv("THOTH_API_URL")
	}
	if cfg.Environment == "" {
		cfg.Environment = os.Getenv("THOTH_ENV")
		if cfg.Environment == "" {
			cfg.Environment = os.Getenv("THOTH_ENVIRONMENT")
		}
	}
	if cfg.UserID == "" {
		cfg.UserID = os.Getenv("THOTH_USER_ID")
	}
	if len(cfg.ApprovedScope) == 0 {
		if scope := os.Getenv("THOTH_APPROVED_SCOPE"); scope != "" {
			parts := strings.Split(scope, ",")
			cfg.ApprovedScope = make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					cfg.ApprovedScope = append(cfg.ApprovedScope, p)
				}
			}
		}
	}
	if cfg.SessionIntent == "" {
		cfg.SessionIntent = os.Getenv("THOTH_SESSION_INTENT")
	}
	if cfg.Purpose == "" {
		cfg.Purpose = strings.TrimSpace(os.Getenv("THOTH_PURPOSE"))
	}
	if cfg.DataClassification == "" {
		cfg.DataClassification = strings.TrimSpace(os.Getenv("THOTH_DATA_CLASSIFICATION"))
	}
	if len(cfg.TaskContext) == 0 {
		cfg.TaskContext = parseJSONMap(os.Getenv("THOTH_TASK_CONTEXT_JSON"))
	}
	if cfg.ModelName == "" {
		cfg.ModelName = strings.TrimSpace(os.Getenv("THOTH_MODEL_NAME"))
	}
	if cfg.ModelProvider == "" {
		cfg.ModelProvider = strings.TrimSpace(os.Getenv("THOTH_MODEL_PROVIDER"))
	}
	if cfg.ModelArtifactID == "" {
		cfg.ModelArtifactID = strings.TrimSpace(os.Getenv("THOTH_MODEL_ARTIFACT_ID"))
	}
	if cfg.ModelArtifactVersion == "" {
		cfg.ModelArtifactVersion = strings.TrimSpace(os.Getenv("THOTH_MODEL_ARTIFACT_VERSION"))
	}
	if len(cfg.AuthContext) == 0 {
		cfg.AuthContext = parseJSONMap(os.Getenv("THOTH_AUTH_CONTEXT_JSON"))
	}
	if len(cfg.DelegationContext) == 0 {
		cfg.DelegationContext = parseJSONMap(os.Getenv("THOTH_DELEGATION_CONTEXT_JSON"))
	}
	if cfg.MCPRuntimeIdentity == "" {
		cfg.MCPRuntimeIdentity = strings.TrimSpace(os.Getenv("THOTH_MCP_RUNTIME_IDENTITY"))
	}
	if len(cfg.RequestMetadata) == 0 {
		cfg.RequestMetadata = parseJSONMap(os.Getenv("THOTH_REQUEST_METADATA_JSON"))
	}
	if cfg.EnforcementTraceID == "" {
		cfg.EnforcementTraceID = os.Getenv("THOTH_ENFORCEMENT_TRACE_ID")
	}
	if cfg.ActionAttestationID == "" {
		cfg.ActionAttestationID = os.Getenv("THOTH_ACTION_ATTESTATION_ID")
	}
	if cfg.Enforcement == "" {
		cfg.Enforcement = os.Getenv("THOTH_ENFORCEMENT_MODE")
		if cfg.Enforcement == "" {
			cfg.Enforcement = os.Getenv("THOTH_ENFORCEMENT")
		}
	}
	if !cfg.FailOpen {
		if raw := strings.TrimSpace(os.Getenv("THOTH_FAIL_OPEN")); raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err == nil {
				cfg.FailOpen = parsed
			}
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	return cfg
}

func toInternalConfig(cfg Config) ithoth.Config {
	internal := ithoth.Config{
		AgentID:          cfg.AgentID,
		TenantID:         cfg.TenantID,
		APIKey:           cfg.APIKey,
		EventIngestToken: cfg.EventIngestToken,
		APIURL:           cfg.APIURL,
		// Enforce a single URL contract for SDK users.
		EnforcerURL:          cfg.APIURL,
		Environment:          cfg.Environment,
		UserID:               cfg.UserID,
		IdentityBinding:      cfg.IdentityBinding,
		ApprovedScope:        cfg.ApprovedScope,
		SessionIntent:        cfg.SessionIntent,
		Purpose:              cfg.Purpose,
		DataClassification:   cfg.DataClassification,
		TaskContext:          cfg.TaskContext,
		ModelName:            cfg.ModelName,
		ModelProvider:        cfg.ModelProvider,
		ModelArtifactID:      cfg.ModelArtifactID,
		ModelArtifactVersion: cfg.ModelArtifactVersion,
		AuthContext:          cfg.AuthContext,
		DelegationContext:    cfg.DelegationContext,
		MCPRuntimeIdentity:   cfg.MCPRuntimeIdentity,
		RequestMetadata:      cfg.RequestMetadata,
		FailOpen:             cfg.FailOpen,
		EnforcementTraceID:   cfg.EnforcementTraceID,
		ActionAttestationID:  cfg.ActionAttestationID,
	}
	if cfg.Enforcement != "" {
		internal.Enforcement = ithoth.EnforcementMode(strings.ToLower(strings.TrimSpace(cfg.Enforcement)))
	}
	return ithoth.ApplyConfigDefaults(internal)
}

// Client is the primary entry point for the Thoth SDK.
type Client struct {
	cfg     Config
	tracer  *ithoth.Tracer
	emitter ithoth.Emitter
	http    *http.Client
}

// DeliveryStatus reports process-local telemetry delivery counters.
type DeliveryStatus = ithoth.DeliveryStatus

// NewClient initializes a Thoth SDK client.
func NewClient(cfg Config) (*Client, error) {
	cfg = applyEnvFallbacks(cfg)
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("thoth: APIURL is required (set Config.APIURL or THOTH_API_URL)")
	}
	internalCfg := toInternalConfig(cfg)
	emitter := ithoth.NewHTTPEmitterWithEventIngestToken(
		internalCfg.APIURL,
		internalCfg.APIKey,
		internalCfg.EventIngestToken,
	)
	sess := ithoth.NewSessionContext(internalCfg)
	tracer := ithoth.NewTracer(internalCfg, sess, emitter)

	c := &Client{
		cfg:     cfg,
		tracer:  tracer,
		emitter: emitter,
		http:    &http.Client{Timeout: cfg.Timeout},
	}
	traceID := internalCfg.EnforcementTraceID
	if traceID == "" {
		traceID = sess.SessionID
	}
	startEvent := ithoth.NewBehavioralEvent(ithoth.BehavioralEventInput{
		AgentID:            internalCfg.AgentID,
		TenantID:           internalCfg.TenantID,
		SessionID:          sess.SessionID,
		UserID:             internalCfg.UserID,
		Purpose:            internalCfg.Purpose,
		DataClassification: internalCfg.DataClassification,
		TaskContext:        cloneAnyMap(internalCfg.TaskContext),
		InitiatedBy:        firstNonEmptyString(internalCfg.TaskContext, "initiated_by", "initiatedBy"),
		TaskID:             firstNonEmptyString(internalCfg.TaskContext, "task_id", "taskId"),
		DelegationChain:    stringSliceFromMap(internalCfg.TaskContext, "chain"),
		SourceType:         ithoth.SourceAgentLLM,
		EventType:          ithoth.EventLLMInvocation,
		ToolName:           "go_sdk",
		Content:            fmt.Sprintf("go_sdk_session_start enforcement=%s", internalCfg.Enforcement),
		Metadata:           map[string]any{"enforcement_trace_id": traceID, "environment": internalCfg.Environment},
		ApprovedScope:      append([]string{}, internalCfg.ApprovedScope...),
		EnforcementMode:    internalCfg.Enforcement,
		SessionToolCalls:   []string{},
	})
	emitter.Emit(&startEvent)

	log.Printf("thoth: client initialized (agent=%q tenant=%q enforcement=%s)",
		cfg.AgentID, cfg.TenantID, internalCfg.Enforcement)
	return c, nil
}

// Close flushes buffered events and releases resources.
func (c *Client) Close() {
	if c.emitter != nil {
		c.emitter.Close()
	}
}

// TelemetryDeliveryStatus returns the current process-local delivery counters.
// Server persistence and customer-visible acknowledgement require a separate
// server-side delivery-status integration.
func (c *Client) TelemetryDeliveryStatus() DeliveryStatus {
	if reporter, ok := c.emitter.(interface{ Status() ithoth.DeliveryStatus }); ok {
		return reporter.Status()
	}
	return DeliveryStatus{}
}

// CloseWithTimeout bounds how long the caller waits for telemetry flushing.
func (c *Client) CloseWithTimeout(timeout time.Duration) DeliveryStatus {
	if closer, ok := c.emitter.(interface {
		CloseWithTimeout(time.Duration) ithoth.DeliveryStatus
	}); ok {
		return closer.CloseWithTimeout(timeout)
	}
	c.Close()
	return c.TelemetryDeliveryStatus()
}

func parseJSONMap(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	if len(parsed) == 0 {
		return nil
	}
	return parsed
}

func firstNonEmptyString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
	}
	return ""
}

func stringSliceFromMap(values map[string]any, key string) []string {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	switch typed := raw.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprintf("%v", item))
			if text != "" {
				out = append(out, text)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}
