# Changelog

All notable changes to `thoth-go` are documented in this file.

## Unreleased

## 0.1.22 - 2026-11-28

### Changed

- A request larger than 4 MiB, the enforcer's default limit, is refused in the SDK before it is
  sent: the call is blocked with the reason `enforcer_request_too_large` and the tool does not run,
  whether or not fail-open is on. Before, the
  enforcer's refusal could arrive as a dropped connection, which fail-open read as an allow. Use
  smaller tool arguments or ask a reviewer for a held action. This check is in the SDK and needs no
  enforcer change.

### Fixed

- With fail-open on, an enforcer reply that could not be understood no longer allows the call; it is blocked, with the reason `enforcer response not understood`, whether or not fail-open is on. Fail-open still covers only an enforcer that cannot be reached or is overloaded (network error, timeout, 429, 5xx); authentication failures still block.

### Known limits

- In observe mode a request that cannot be built (a non-finite number, an unserialisable value) is not sent and leaves no record: it appears nowhere in the would-have-blocked summary.

### Added

- Local scan detects labelled medical record numbers and labelled dates of birth in tool
  arguments: two new `dlp` categories, `mrn` and `dob`, reported as a category and a count (the
  matched text is never kept or sent). A match needs a label next to the value: `MRN`, `medical
  record number`, `patient id` or `chart number` followed by an identifier; `DOB`, `date of birth`,
  `birthdate`, `birthday` or `born` followed by an ISO, numeric day-month-year or written-month
  date with a year from 1900 to 2026. A bare number or a bare date is not matched. These are
  pattern detectors: they have false positives (for example a UUID right after `patient id`) and
  false negatives (for example `user_dob`, two-digit years, or a year after 2026), and they make
  no compliance or PHI claim. The detector set's `ruleset_hash` is `9e7e25ec9d1f280b12f6006726cfc9efdaf5a0dc24585b08eb513e140ff3ae46`: workspace
  owners add it to `accepted_scanner_ruleset_hashes` before relying on a client that sends it. The email detector's quantifiers are now bounded (local part up to 64 characters, domain up to 253), so scanning long text is linear; an address whose local part is one run of more than 64 letters or digits is no longer matched. The scan runs in your process; the server side needs the matching Thoth platform release. There `mrn` and `dob` are findings only (rule conditions, evidence): the server does not redact them from what a tool receives unless redaction for them is switched on, which is an explicit workspace choice. An enforcer built between 8 and 24 November rejects a report containing `mrn` or `dob` with a 422, because it only knows the original five categories, and the SDK blocks that call even with fail-open on. The enforcer in production today ignores the new `client_findings` field.

- `Client.ReportUsage(thoth.Usage{PromptTokens, CompletionTokens, CostUSD})` reports the model
  usage behind a governed call, so a workspace's daily budget for the agent has something to
  count. It is sent with the next governed call as `prompt_tokens`, `completion_tokens` and,
  only if you set `CostUSD`, `estimated_cost_usd`, then forgotten (sent once; resent if the call
  did not reach the server). Tokens first: Thoth never works dollars out from tokens. Zero,
  negative and non-finite values are ignored; one report is capped at 10,000,000 tokens and
  $1,000. Additive: nothing changes unless you call it.
- Opt-in withholding of values at the source. Set `Config.DataHandlingToolArguments`
  (`hash`, `redact` or `drop`) and `Config.DataHandlingPrompts` (`hash` or `drop`), or the
  environment variables `THOTH_DATA_HANDLING_TOOL_ARGUMENTS`,
  `THOTH_DATA_HANDLING_PROMPTS` and `THOTH_DATA_HANDLING_SALT`. Hashes are
  HMAC-SHA256 with a client-held salt (`Config.DataHandlingSalt`, else a random
  per-process salt). The enforce request declares what was applied in
  `data_handling`, a rule that needs argument values holds the call
  (`args_withheld`) and says why, and modified arguments are never applied to a
  call whose arguments were withheld: if the server returns a rewrite anyway,
  including on an approved hold, the call fails closed (the tool does not run,
  `*PolicyViolationError`) because that is a server or contract problem. Nothing
  changes when unset; an invalid value makes `NewClient` return an error. No new
  dependencies. A whole-number float hashes as an integer (`3.0` is `3`), as in the
  TypeScript SDK. The `args_withheld` hold needs a Thoth platform release that includes it (server change #3978): against an enforcer without it, hashed or redacted argument values are evaluated as if they were real, so a rule on argument values would not hold and the call could be allowed.
- Local scanning when tool arguments are withheld. With
  `DataHandlingToolArguments` set to `hash`, `redact` or `drop`, the SDK scans the
  raw arguments (and the destination host in `RequestMetadata`) in your process
  before withholding them, and sends `client_findings` next to `data_handling`:
  counts and categories of credentials, email addresses, phone numbers, SSN-shaped
  numbers and confidentiality phrases, whether a path looks sensitive, a
  destination hostname, and recipient domains. The enforcer must be on a Thoth platform release that accepts `client_findings`. The report never contains values,
  paths, local parts or display names. The detectors are heuristic. The scanner
  identifies itself as `atensec-thoth-go` with ruleset `thoth-detectors.v1`,
  ruleset hash
  `9e7e25ec9d1f280b12f6006726cfc9efdaf5a0dc24585b08eb513e140ff3ae46`; a workspace
  relies on the report only after it sets `accept_local_scan` and lists that hash
  in `accepted_scanner_ruleset_hashes`. A check that fails, hits the depth or value
  bound, or would not fit the 4 KB limit is left out of `scanned` instead of
  reported clean. `THOTH_DATA_HANDLING_LOCAL_SCAN=off` (or
  `DataHandlingLocalScan: "off"`) sends no findings. A workspace with
  `require_client_findings` holds calls from a client that withholds arguments and
  sends no findings. The detector spec is embedded in the module and refused if it
  does not match its hash. Go maps have no order, so keys are read in sorted order:
  recipient domains from different fields are listed in that order.
- `PolicyViolationError.Reason` explains an `args_withheld` hold and points to
  `THOTH_DATA_HANDLING_TOOL_ARGUMENTS`.

## 0.1.21 - 2026-11-06

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
