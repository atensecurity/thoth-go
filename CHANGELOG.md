# Changelog

All notable changes to `thoth-go` are documented in this file.

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
