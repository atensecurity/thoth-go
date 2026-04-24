// Package thoth provides the Aten Thoth SDK for instrumenting Go AI agents
// with governance, policy enforcement, and behavioral monitoring.
//
// Thoth wraps your agent's tool functions with pre-execution policy checks
// (enforcer) and asynchronous behavioral event emission (HTTP). Enforcement
// is fail-closed: if the enforcer is unreachable, your tool call is blocked
// and a policy violation is returned.
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
//	THOTH_TENANT_ID  — tenant identifier
//	THOTH_AGENT_ID   — agent identifier
//	THOTH_API_URL    — unified tenant API base URL override (enforcement + events)
//	THOTH_ENV        — environment scope (default: prod)
//	THOTH_ENFORCEMENT_TRACE_ID — explicit cross-service trace ID override
//	THOTH_USER_ID    — user identifier for policy evaluation
//	THOTH_APPROVED_SCOPE — comma-delimited approved tool names
//	THOTH_SESSION_INTENT — HIPAA minimum-necessary session intent
package thoth

import (
	"fmt"
	"log"
	"net/http"
	"os"
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
	// Env fallback: THOTH_ENV.
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

	// EnforcementTraceID sets an explicit trace correlation ID for enforcement
	// requests. When empty, session ID is used.
	// Env fallback: THOTH_ENFORCEMENT_TRACE_ID.
	EnforcementTraceID string

	// Timeout is the HTTP timeout for enforcer calls. Default: 5s.
	Timeout time.Duration

	// Enforcement controls how policy violations are handled.
	// Default: "progressive".
	Enforcement string
}

func applyEnvFallbacks(cfg Config) Config {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("THOTH_API_KEY")
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
	if cfg.EnforcementTraceID == "" {
		cfg.EnforcementTraceID = os.Getenv("THOTH_ENFORCEMENT_TRACE_ID")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	return cfg
}

func toInternalConfig(cfg Config) ithoth.Config {
	internal := ithoth.Config{
		AgentID:  cfg.AgentID,
		TenantID: cfg.TenantID,
		APIKey:   cfg.APIKey,
		APIURL:   cfg.APIURL,
		// Enforce a single URL contract for SDK users.
		EnforcerURL:        cfg.APIURL,
		Environment:        cfg.Environment,
		UserID:             cfg.UserID,
		IdentityBinding:    cfg.IdentityBinding,
		ApprovedScope:      cfg.ApprovedScope,
		SessionIntent:      cfg.SessionIntent,
		EnforcementTraceID: cfg.EnforcementTraceID,
	}
	if cfg.Enforcement != "" {
		internal.Enforcement = ithoth.EnforcementMode(cfg.Enforcement)
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

// NewClient initializes a Thoth SDK client.
func NewClient(cfg Config) (*Client, error) {
	cfg = applyEnvFallbacks(cfg)
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("thoth: APIURL is required (set Config.APIURL or THOTH_API_URL)")
	}
	internalCfg := toInternalConfig(cfg)
	emitter := ithoth.NewHTTPEmitter(internalCfg.APIURL, internalCfg.APIKey)
	sess := ithoth.NewSessionContext(internalCfg)
	tracer := ithoth.NewTracer(internalCfg, sess, emitter)

	c := &Client{
		cfg:     cfg,
		tracer:  tracer,
		emitter: emitter,
		http:    &http.Client{Timeout: cfg.Timeout},
	}

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
