# Changelog

All notable changes to `thoth-go` are documented in this file.

## Unreleased

### Added

- When a held action is approved or denied, the decision and `PolicyViolationError`
  carry the signed `TerminalReceipt`, and `Receipt` keeps the receipt written
  when it was held (it was dropped). While a hold is pending, the SDK logs one
  line saying where to approve or deny it. `EnforcementDecision` also carries
  `ProfileID`, `ProfileVersion`, `TenantDeclarationsStatus` and
  `RiskClassification` when the enforcer returns them. Event telemetry now
  includes the receipt's `signature_key_id` and the terminal receipt.

### Fixed

- A held call that is approved now runs with the arguments the enforcer redacted
  when it held the call. The approval comes back as a plain ALLOW, so the call
  used to start with the original arguments (an approved email to an outside
  recipient was sent with its card number). A modification the SDK cannot map
  back onto the call, or one that arrives with no arguments, now returns a
  `PolicyViolationError` instead of running the original arguments, and a tool
  with its own `args` parameter is no longer misread as the positional form.
- Enforce and hold-status requests send the API key in both `X-Api-Key` and
  `Authorization: Bearer`, as event ingestion already does. The SDK sent only
  Bearer, so behind an ingress that strips `Authorization` every call was
  blocked.
- A held call now waits up to 15 minutes for approval, as the Python and
  TypeScript SDKs do. The wait was fixed at 30 seconds with no way to change it,
  so a person approving in Slack or the dashboard a minute later found the call
  already blocked. Set `Config.StepUpTimeout` for a different limit (a shorter
  one suits unattended jobs).
- A step-up decision with no hold token is refused at once, instead of polling
  an empty token for the whole wait before blocking.
- The SDK no longer writes your tool's own errors to the process log. Errors
  that are not Thoth's are returned as they came, and a tool error can carry
  URLs, tokens or data.
- A call the enforcer allows with its arguments redacted or filtered (outbound
  DLP redaction, or purpose-limited retrieval) now runs with the modified
  arguments. The enforcer sends that as `decision` ALLOW next to
  `authorization_decision` MODIFY, and the SDK used to read only `decision`, so the
  tool ran with the original arguments while the decision log said MODIFY. A
  stricter `decision` (BLOCK, STEP_UP or DEFER) still wins. The TypeScript SDK
  was not affected.

### Changed

- `Config.APIURL` and `THOTH_API_URL` ignore blank (whitespace-only) values, so
  the order is always `Config.APIURL`, then `THOTH_API_URL`, then
  `https://api.atensecurity.com`.
- `Config.APIURL` defaults to `DefaultAPIURL` (`https://api.atensecurity.com`),
  the API for trial and self-serve workspaces, when neither `Config.APIURL` nor
  `THOTH_API_URL` is set. Previously `NewClient` returned an error. Enterprise
  workspaces keep setting their own host; an explicit value always wins.

## 0.1.20 - 2026-10-18

### Added

- Tool inventory: `RegisterToolInventory` sends tool names, descriptions and
  input-schema structure to your Thoth API, so Thoth can propose an effect
  class for an admin to confirm. Instrumenting a tool map reports the tool
  names from a goroutine, off the startup path, with a 2-second timeout.
  Proposals are advisory: they never grant execution, and only an admin's
  confirmation changes decisions.

### Privacy

- Schema `default`, `example`, `examples`, `const` and `enum` values are
  removed recursively before sending; parameters with those names are kept.
  Descriptions are sent as written, so keep secrets out of tool metadata.
- Set `THOTH_TOOL_INVENTORY=off` to disable collection.

## 0.1.19 - 2026-09-11

### Added

- Added a per-action attestation ID, generated for each tool call unless the
  caller supplies one, and propagated it through enforcement decisions,
  behavioral events, logs, and policy errors for deterministic correlation.
- Added model name/provider/artifact context, authentication and delegation
  context, MCP runtime identity, and caller metadata to authorization requests.
- Added public process-local delivery status and bounded shutdown APIs.

### Changed

- Minimized retained HTTP and SQS telemetry with an explicit allowlist. Tool
  arguments, free-text context, results, errors, explanations, full receipts,
  and unknown metadata remain available to authorization but are not retained
  by default.
- Added bounded HTTP and SQS delivery retries with stable event and FIFO
  deduplication identifiers. Retrying telemetry never re-executes a governed
  tool or repeats its authorization decision.
- Added SQS partial-batch failure handling, process-local delivery counters,
  bounded shutdown through `CloseWithTimeout`, and a five-second overall HTTP
  request timeout.
- Expanded the public decision-envelope compatibility contract and standalone
  module tests for the new authorization and evidence fields.
- Documented the telemetry privacy boundary and the limits of process-local
  delivery status.

## 0.1.18 - 2026-06-20

### Changed

- Added configurable resilience mode via `Config.FailOpen` / `THOTH_FAIL_OPEN`.
  When enabled, enforcer transport failures and retryable statuses (`429`, `5xx`)
  return `ALLOW` so tool execution can continue.
- Auth failures (`401`/`403`) remain fail-closed and continue returning `BLOCK`.
- Added regression coverage in internal and public SDK tests for fail-open/fail-closed behavior.
- Added vendor-runtime observability coexistence tests for Datadog, LangSmith, OpenTelemetry,
  and Sentry in an isolated compat test module (`sdk/thoth/compat`).
- Added compatibility matrix CI coverage for Go runtime-stack coexistence verification.

## 0.1.17 - 2026-05-14

### Changed

- Added SDK handling for `MODIFY` and `DEFER` decision types:
  - `MODIFY` rewrites tool arguments before execution via the `ModifiedToolArgs` field on `EnforcementDecision`.
  - `DEFER` surfaces a `PolicyViolationError` with defer timeout context (`DeferTimeoutSeconds`) so callers can retry later.
- Expanded enforcement decision aliases: `DENY→BLOCK`, `CHALLENGE/ESCALATE→STEP_UP`, `TRANSFORM→MODIFY`, `HOLD→DEFER`.
- Added `observe` as the canonical enforcement mode (previously `shadow`); `shadow` remains accepted as a legacy alias.
- Added expanded policy/telemetry context propagation fields on `Config`:
  `EnforcementTraceID`, `SessionIntent`, `Purpose`, `DataClassification`, `TaskContext`.
- Added `DecisionEnvelopeVersion`, `EnforcementTraceID`, `FastMLFeatures`, `ScoreComponents`,
  `TopContributors`, and `DecisionEvidence` to `EnforcementDecision` and `PolicyViolationError`
  for full parity with Python SDK v0.1.16 decision envelope schema.
- Improved HTTP diagnostics for auth/ingress failures with actionable hints for 401/403 responses.

## 0.1.15 - 2026-05-05

### Changed

- Declared the current stable Go SDK release line in a versioned changelog.
- Added customer-facing release-note structure for future tagged releases.
