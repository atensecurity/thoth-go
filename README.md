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
export THOTH_API_URL="https://enforce.<tenant>.<apex-domain>"
export THOTH_TENANT_ID="<tenant>"
export THOTH_AGENT_ID="invoice-processor-v2"
```

`THOTH_API_URL` is required. The SDK uses this single URL for both:

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

## Notes

- Enforcement is fail-open on transport errors (tool execution continues if the enforcer is unreachable).
- Use `Client.StartSession(...)` for per-request session isolation in servers.
- See `examples/` for end-to-end usage with OpenAI and Anthropic loops.
