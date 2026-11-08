# Thoth Go SDK

Go SDK for Thoth runtime governance: policy enforcement, step-up approval, and behavioral event emission for agent tool calls.

## Install

```bash
go get github.com/atensecurity/thoth-go
```

## Required configuration

Set these environment variables (or pass equivalent fields in `thoth.Config`):

```bash
export THOTH_API_KEY="thoth_live_..."
export THOTH_API_URL="https://api.atensecurity.com" # optional: trial and self-serve default; Enterprise: your enforce. host
export THOTH_TENANT_ID="<tenant>"
export THOTH_AGENT_ID="invoice-processor-v2"
```

Optional policy-context variables:

```bash
export THOTH_USER_ID="user-123"
export THOTH_APPROVED_SCOPE="read_file,search_docs"
export THOTH_SESSION_INTENT="triage"
export THOTH_EVENT_INGEST_TOKEN="ingest-token-optional"
export THOTH_ENFORCEMENT_MODE="block" # optional override; default is block (deny)
export THOTH_FAIL_OPEN="false" # optional; true allows on enforcer network/429/5xx failures
export THOTH_LOG_LEVEL="DEBUG" # optional; falls back to LOG_LEVEL when unset
export THOTH_DATA_HANDLING_TOOL_ARGUMENTS="redact" # optional: hash | redact | drop (see "Withholding values from Thoth")
export THOTH_DATA_HANDLING_PROMPTS="hash"          # optional: hash | drop
export THOTH_DATA_HANDLING_SALT="a-long-random-secret" # optional: salt for hash; random per process when unset
export THOTH_DATA_HANDLING_LOCAL_SCAN="off"        # optional: on (default) | off
```

`THOTH_API_URL` defaults to `https://api.atensecurity.com`, the API for trial and
self-serve workspaces. Enterprise workspaces set their own host. The SDK uses
this single URL for both:

- `POST /v1/enforce`
- `POST /v1/events/batch`

## Quick start

```go
package main

import (
  "context"
  "errors"
  "fmt"
  "log"
  "os"

  "github.com/atensecurity/thoth-go"
)

func main() {
  client, err := thoth.NewClient(thoth.Config{
    APIKey:   os.Getenv("THOTH_API_KEY"),
    APIURL:   os.Getenv("THOTH_API_URL"),
    TenantID: os.Getenv("THOTH_TENANT_ID"),
    AgentID:  os.Getenv("THOTH_AGENT_ID"),
  })
  if err != nil {
    log.Fatal(err)
  }
  defer client.Close()

  govSearch := client.WrapTool("search_docs", func(ctx context.Context, query string) (string, error) {
    return "found: " + query, nil
  })

  out, err := govSearch(context.Background(), "quarterly report")
  if err != nil {
    var pve *thoth.PolicyViolationError
    if errors.As(err, &pve) {
      log.Printf("blocked: %s (violation_id=%s)", pve.Reason, pve.ViolationID)
      return
    }
    log.Fatal(err)
  }

  fmt.Println(out)
}
```

## Framework helper maps

Use map wrappers for OpenAI/Anthropic-style tool loops where tool args are `map[string]any`:

```go
wrappedAnthropic := client.InstrumentAnthropic(map[string]thoth.ToolFunc{
  "search_docs": func(ctx context.Context, args map[string]any) (any, error) {
    return "found: " + args["query"].(string), nil
  },
})

// Legacy aliases remain supported:
wrappedOpenAI := client.WrapOpenAITools(map[string]thoth.ToolFunc{
  "search_docs": func(ctx context.Context, args map[string]any) (any, error) {
    return "found: " + args["query"].(string), nil
  },
})

_, _ = wrappedAnthropic["search_docs"](context.Background(), map[string]any{"query": "retention policy"})
_, _ = wrappedOpenAI["search_docs"](context.Background(), map[string]any{"query": "incident response"})
```

## Withholding values from Thoth

> Not in a published release yet: this ships in the next release of `thoth-go`.

By default the SDK sends a tool call's argument values to Thoth so value-based rules and outbound
data checks can run. You can opt in, per client, to keeping the values on your side. With nothing
set, behavior is unchanged.

```go
client, err := thoth.NewClient(thoth.Config{
  DataHandlingToolArguments: "redact", // or "hash" | "drop"
  DataHandlingPrompts:       "hash",   // or "drop"
  DataHandlingSalt:          os.Getenv("MY_THOTH_SALT"), // optional, see below
})
```

`THOTH_DATA_HANDLING_TOOL_ARGUMENTS`, `THOTH_DATA_HANDLING_PROMPTS`, `THOTH_DATA_HANDLING_SALT` and
`THOTH_DATA_HANDLING_LOCAL_SCAN` set the same options from the environment; a `Config` field wins
over its variable. An invalid value makes `NewClient` return an error. The SDK never falls back to
sending the raw value. Sessions from `StartSession` use the client's setting.

**Tool arguments**

- `hash`: keys and structure are kept, and each value (string, number, boolean) becomes
  `hmac-sha256:<hex>`, an HMAC-SHA256 keyed with your salt over the value's canonical JSON. `nil`
  stays `null`.
- `redact`: keys and structure are kept, and each value becomes `"<redacted>"`.
- `drop`: no arguments are sent.

Nested arguments are walked to depth 16 and 5,000 values. Anything beyond that becomes `"<truncated>"`.
Values that are not plain maps, slices, strings and numbers (structs, typed slices and maps) are read
through their JSON form, so `json` tags and `MarshalJSON` decide the keys and values that are hashed.
Go writes a whole-number float such as `3.0` as `3`, as JavaScript does, so `3` and `3.0` hash the
same here; the Python SDK, which tells them apart, hashes `3.0` differently. Go maps have no order, so
keys are read in sorted order.

**Prompts.** The SDK has no prompt field of its own. The mode applies to the context you pass in
`TaskContext`, `AuthContext`, `DelegationContext`, `IdentityBinding` and `RequestMetadata`: values
under prompt-bearing key names (`prompt`, `message(s)`, `input`, `query`, `text`, `content`,
`instruction(s)`, `task`, `goal`, `description`, `summary`, `note(s)`, `history`, `transcript`,
`response`, `output` and similar, at any depth, ignoring case, `_` and `-`) are hashed or omitted, and
any other string longer than 512 characters is hashed (`hash`) or replaced by `"<redacted>"` (`drop`).
Identifiers, `Purpose`, `DataClassification` and `SessionIntent` are sent as given, so do not put user
text in them.

**The salt.** Hashing uses a salt that only your process holds; Thoth has no key to it. Equal values
produce equal hashes only under the same salt. With the default random salt that means within one
process. Set the same `THOTH_DATA_HANDLING_SALT` on every process that should match values. Anyone who
has the salt can confirm a guess at a low-entropy value, so keep it secret.

**Local scanning.** So checks that need values can still run, the SDK scans the raw arguments in your
process before withholding them (and the destination host in `RequestMetadata`), and sends the result
as `client_findings` next to `data_handling`:

- It reports counts and categories (credentials, email addresses, phone numbers, SSN-shaped numbers,
  confidentiality phrases), whether a `path` or `paths` value looks sensitive, a destination hostname,
  and recipient domains. It never reports values, paths, the local part of an address, display names or
  message text.
- The detectors are heuristic regular expressions from a versioned spec (`thoth-detectors.v1`). A
  finding is a signal, not proof that data is sensitive, and no finding is not proof that it is not.
- The report names the scanner (`atensec-thoth-go`), its version (the `thoth-go` module version in your
  build) and its ruleset hash. Thoth cannot verify a client scan: a workspace relies on it only after the
  owner sets `accept_local_scan` and lists the hash in `accepted_scanner_ruleset_hashes`. The hash this
  SDK sends is `db797fde60f300719b9dac8a360efd6ce8b1f7313587cc714aebf7a93428434b`. Findings only ever
  raise a decision.
- A check that cannot finish (a panic, arguments deeper than 16 levels or beyond 5,000 values for `dlp`
  and `recipient`, non-ASCII text in recipient fields that engines read differently, a report over 4 KB)
  is left out of `scanned`, so Thoth sees it as missing, not clean. Arguments that are not an object send
  no findings.
- A workspace with `require_client_findings` holds every call from a client that withholds arguments and
  sends no findings, so it needs a client that ships DLP scanning. If your workspace turns that on, keep
  local scanning on.
- It is on whenever tool arguments are withheld. Set `DataHandlingLocalScan: "off"` or
  `THOTH_DATA_HANDLING_LOCAL_SCAN=off` to send no findings. With only `DataHandlingPrompts` set,
  arguments are sent as before and nothing is scanned.
- Go's regular expressions are RE2: `\b`, `\w` and `\d` are ASCII, as the spec requires, and `\s` is
  rewritten to the spec's ASCII whitespace class. Case-insensitive matching folds the Kelvin sign and the
  long s to `k` and `s`, as the server's Python does, so on those characters this SDK can count more than
  an ASCII-only engine, never less.

**What still reaches Thoth.** Tool names, decisions, session and user ids, agent and tenant ids, timing,
and the tool-call sequence. Key names are sent in `hash` and `redact` mode, and not in `drop`. With local
scanning on, also the findings above: counts, categories, a destination hostname and recipient domains.
The SDK declares what it applied, and Thoth records that declaration with the decision.

**What you give up.** Rules that read argument values (path patterns, regular expressions, free-text
keywords) and outbound data checks cannot run on values Thoth does not have. When such a rule exists,
the call is held (`STEP_UP` with reason code `args_withheld`) instead of being decided on values it cannot
see, and the `PolicyViolationError` reason says so. A server never returns modified arguments for a call
whose arguments were withheld; if one ever does, on a `MODIFY` decision or on an approved hold, the SDK
fails closed: the tool does not run and a `*PolicyViolationError` says the server returned an argument
rewrite although arguments were withheld, which points to a server or contract problem.

This option limits what Thoth receives; it does not make any statement about what your own tools, logs
or other services do with the values.

## Notes

- Enforcement is fail-closed by default. Set `Config.FailOpen` or `THOTH_FAIL_OPEN=true` to allow tool execution when the enforcer is unavailable (network/429/5xx). Auth failures remain blocked.
- `PolicyViolationError` includes `DecisionReasonCode` and `ActionClassification` for deterministic policy analytics.
- `StepUpRequiredError` is returned when a pending step-up approval is surfaced with a hold token; step-up timeout/deny outcomes remain `PolicyViolationError` blocks.
- Decision debug logs include `hold_token` when present (`STEP_UP` flows). Use `THOTH_LOG_LEVEL` (`DEBUG`, `INFO`, `WARN`, `ERROR`) to tune SDK decision-log verbosity; fallback is `LOG_LEVEL`.
- Use `Client.StartSession(...)` for per-request session isolation in servers.
- See `examples/` for end-to-end usage with OpenAI and Anthropic loops.
