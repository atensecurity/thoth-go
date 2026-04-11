// Command anthropic demonstrates the Thoth Go SDK wrapping tools for use with
// an Anthropic Claude agentic loop.
//
// To run:
//
//	ANTHROPIC_API_KEY=sk-ant-...        \
//	THOTH_API_KEY=your-api-key          \
//	THOTH_API_URL=https://enforce.acme-corp.aten.security \
//	THOTH_TENANT_ID=acme-corp           \
//	THOTH_AGENT_ID=support-bot-v2       \
//	go run ./sdk/thoth/examples/anthropic/
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	sdk "github.com/atensecurity/thoth-go"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	client, err := sdk.NewClient(sdk.Config{
		APIKey:   envOr("THOTH_API_KEY", ""),
		APIURL:   envOr("THOTH_API_URL", ""),
		TenantID: envOr("THOTH_TENANT_ID", "demo-tenant"),
		AgentID:  envOr("THOTH_AGENT_ID", "support-bot-v2"),
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("thoth.NewClient: %w", err)
	}
	defer client.Close()

	searchDocs := client.WrapToolFunc("search_docs", func(_ context.Context, args map[string]any) (any, error) {
		query, _ := args["query"].(string)
		return fmt.Sprintf("[search results for %q]", query), nil
	})

	sendEmail := client.WrapToolFunc("send_email", func(_ context.Context, args map[string]any) (any, error) {
		to, _ := args["to"].(string)
		subject, _ := args["subject"].(string)
		return fmt.Sprintf("email sent to %s: %q", to, subject), nil
	})

	toolCalls := simulateAnthropicResponse()
	for _, call := range toolCalls {
		switch call.Name {
		case "search_docs":
			result, err := searchDocs(ctx, call.Input)
			printResult("search_docs", result, err)
		case "send_email":
			result, err := sendEmail(ctx, call.Input)
			printResult("send_email", result, err)
		default:
			log.Printf("unknown tool: %s", call.Name)
		}
	}

	return nil
}

type toolUseBlock struct {
	Name  string
	Input map[string]any
}

func simulateAnthropicResponse() []toolUseBlock {
	return []toolUseBlock{
		{Name: "search_docs", Input: map[string]any{"query": "access control policies"}},
		{Name: "send_email", Input: map[string]any{
			"to":      "alice@acme.corp",
			"subject": "Access policy summary",
		}},
	}
}

func printResult(tool string, result any, err error) {
	if err == nil {
		out, _ := json.Marshal(result)
		fmt.Printf("[%s] result: %s\n", tool, out)
		return
	}
	var pve *sdk.PolicyViolationError
	if errors.As(err, &pve) {
		fmt.Printf("[BLOCKED] %s: %s (violation_id=%s)\n", tool, pve.Reason, pve.ViolationID)
		return
	}
	fmt.Printf("[ERROR] %s: %v\n", tool, err)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
