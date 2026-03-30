// Command openai demonstrates the Thoth Go SDK wrapping tools for use with
// an OpenAI function-calling / tool-calling loop.
//
// To run:
//
//	OPENAI_API_KEY=sk-...               \
//	THOTH_API_KEY=your-api-key          \
//	THOTH_TENANT_ID=acme-corp           \
//	THOTH_AGENT_ID=support-bot-v2       \
//	go run ./sdk/thoth/examples/openai/
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

	readFile := client.WrapToolFunc("read_file", func(_ context.Context, args map[string]any) (any, error) {
		path, _ := args["path"].(string)
		return fmt.Sprintf("[contents of %s]", path), nil
	})

	toolCalls := simulateOpenAIResponse()
	for _, call := range toolCalls {
		var args map[string]any
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			log.Printf("bad arguments for %s: %v", call.Name, err)
			continue
		}
		switch call.Name {
		case "search_docs":
			result, err := searchDocs(ctx, args)
			printResult("search_docs", result, err)
		case "read_file":
			result, err := readFile(ctx, args)
			printResult("read_file", result, err)
		default:
			log.Printf("unknown tool: %s", call.Name)
		}
	}

	return nil
}

type functionCall struct {
	Name      string
	Arguments string
}

func simulateOpenAIResponse() []functionCall {
	return []functionCall{
		{Name: "search_docs", Arguments: `{"query":"access control policies"}`},
		{Name: "read_file", Arguments: `{"path":"/etc/policies/access.yaml"}`},
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
