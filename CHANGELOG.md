# Changelog

All notable changes to `thoth-go` are documented in this file.

## 0.1.17 - 2026-05-14

### Changed

- Added SDK handling for `MODIFY` and `DEFER` decision types:
  - `MODIFY` rewrites tool arguments before execution via the `ModifiedArgs` field on `EnforcementDecision`.
  - `DEFER` surfaces a `PolicyViolationError` with defer timeout context (`DeferTimeout`) so callers can retry later.
- Expanded enforcement decision aliases: `DENY→BLOCK`, `CHALLENGE/ESCALATE→STEP_UP`, `TRANSFORM→MODIFY`, `HOLD→DEFER`.
- Added `observe` as the canonical enforcement mode (previously `shadow`); `shadow` remains accepted as a legacy alias.
- Added expanded policy/telemetry context propagation fields on `Config`:
  `EnforcementTraceID`, `SessionIntent`, `Purpose`, `DataClassification`, `TaskContext`.
- Added expanded `PolicyViolationError` metadata for downstream logging and incident handling:
  `DecisionReason`, `ModelFeatures`, `ModelSignals`, `PackVersion`, `RuleVersion`, `SignedReceiptPayload`.
- Improved HTTP diagnostics for auth/ingress failures with actionable hints for 401/403 responses.

## 0.1.15 - 2026-05-05

### Changed

- Declared the current stable Go SDK release line in a versioned changelog.
- Added customer-facing release-note structure for future tagged releases.
