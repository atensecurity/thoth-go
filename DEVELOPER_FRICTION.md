# Go SDK Developer Friction (Measured 2026-06-19)

## Scope and method
- Environment: Linux sandbox with restricted outbound DNS unless escalated.
- External install command attempted: `go get github.com/atensecurity/thoth-go`.

## Time to first event
- `go get github.com/atensecurity/thoth-go`: **failed in 0.02s** due DNS restriction to `proxy.golang.org`.
- Local regression test run (with network-enabled module resolution):
  - `go test ./...` in `backend/go/sdk/thoth`: **0.349s**.
  - Confirms SDK execute path and new fail-open regression test pass.

## Instrumentation lines required
- Typical setup is client init + wrapped tool declaration.
- Practical first-governed-tool code is **6-9 lines** depending on error handling.
- Result: close, but not consistently at the "5 lines or fewer" pilot target.

## Error clarity observed
- Go errors clearly identify enforcer transport failures and HTTP status failures.
- New fail-open mode is explicit (`Config.FailOpen` / `THOTH_FAIL_OPEN`) and keeps auth failures blocked.

## If a developer is confused
- They will often interpret `proxy.golang.org` failures as module or SDK faults rather than network controls.
- They may miss that `THOTH_FAIL_OPEN` exists unless reading README/config docs.

## Top 3 friction points likely to stall a pilot
1. External module resolution requires outbound access to Go proxy infrastructure.
2. No turnkey single-call setup that only needs `THOTH_API_KEY` and `THOTH_API_URL`.
3. Side-by-side instrumentation compatibility matrix (LangSmith/Otel/Datadog/Sentry) is not enforced by Go CI tests.
