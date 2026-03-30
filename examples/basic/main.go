// Command basic demonstrates the Thoth Go SDK wrapping a mock LLM agent tool.
//
// Run with a real API key:
//
//	THOTH_API_KEY=your-api-key             \
//	THOTH_TENANT_ID=acme-corp              \
//	THOTH_AGENT_ID=invoice-agent-v1        \
//	go run ./sdk/thoth/examples/basic/
//
// Without environment variables the example uses empty defaults, so you can
// run it out of the box (enforcer calls will fail-open with ALLOW):
//
//	go run ./sdk/thoth/examples/basic/
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
		AgentID:  envOr("THOTH_AGENT_ID", "invoice-processor-v1"),
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("thoth.NewClient: %w", err)
	}
	defer client.Close()

	searchDocs := client.WrapTool("search_docs", func(_ context.Context, query string) (string, error) {
		return fmt.Sprintf("[doc] results for query: %q", query), nil
	})

	result, err := searchDocs(ctx, "Q3 earnings")
	if err != nil {
		handleToolError("search_docs", err)
	} else {
		fmt.Printf("search_docs result: %s\n", result)
	}

	readInvoice := client.WrapToolFunc("read_invoice", func(_ context.Context, args map[string]any) (any, error) {
		invoiceID, _ := args["invoice_id"].(string)
		return map[string]any{
			"invoice_id": invoiceID,
			"amount":     1500.00,
			"currency":   "USD",
			"status":     "pending",
		}, nil
	})

	invoiceResult, err := readInvoice(ctx, map[string]any{"invoice_id": "INV-00123"})
	if err != nil {
		handleToolError("read_invoice", err)
	} else {
		out, _ := json.MarshalIndent(invoiceResult, "", "  ")
		fmt.Printf("read_invoice result:\n%s\n", out)
	}

	sess, err := client.StartSession(ctx, "invoice-processor-v1", "")
	if err != nil {
		return fmt.Errorf("StartSession: %w", err)
	}
	defer sess.Close()

	fmt.Printf("started session: %s\n", sess.ID)

	approvePayment := sess.WrapTool("approve_payment", func(_ context.Context, invoice string) (string, error) {
		return fmt.Sprintf("payment approved for %s", invoice), nil
	})

	payResult, err := approvePayment(ctx, "INV-00123")
	if err != nil {
		handleToolError("approve_payment", err)
	} else {
		fmt.Printf("approve_payment result: %s\n", payResult)
	}

	fmt.Println("example complete")
	return nil
}

func handleToolError(tool string, err error) {
	var pve *sdk.PolicyViolationError
	var sue *sdk.StepUpRequiredError
	switch {
	case errors.As(err, &pve):
		fmt.Printf("[BLOCKED] %s: %s (violation_id=%s)\n", tool, pve.Reason, pve.ViolationID)
	case errors.As(err, &sue):
		fmt.Printf("[STEP-UP] %s: %s — waiting for approval (hold_token=%s)\n", tool, sue.Reason, sue.HoldToken)
	default:
		fmt.Printf("[ERROR] %s: %v\n", tool, err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
