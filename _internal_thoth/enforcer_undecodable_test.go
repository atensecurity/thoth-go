package thoth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

// A 2xx whose body cannot be understood is not an outage: it blocks in both modes.
func TestEnforcerClient_UnparseableSuccessBodyBlocksInBothModes(t *testing.T) {
	t.Parallel()
	bodies := map[string]string{
		"wrong typed field": `{"decision":"BLOCK","risk_score":"high"}`,
		"html page":         `<html><body>Welcome</body></html>`,
		"array":             `[]`,
		"empty body":        ``,
		"truncated json":    `{"decision":"ALLOW","reason":"ok`,
	}
	for name, body := range bodies {
		for _, failOpen := range []bool{true, false} {
			body, failOpen := body, failOpen
			label := name + "/fail-closed"
			if failOpen {
				label = name + "/fail-open"
			}
			t.Run(label, func(t *testing.T) {
				t.Parallel()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(body))
				}))
				defer srv.Close()
				client := thoth.NewEnforcerClient(srv.URL, "", failOpen)
				dec, _ := client.Check(context.Background(), thoth.CheckRequest{ToolName: "tool", SessionID: "sess-1"})
				if dec.Decision != thoth.DecisionBlock {
					t.Fatalf("decision = %q, want BLOCK", dec.Decision)
				}
				if !strings.Contains(dec.Reason, "not understood") {
					t.Errorf("reason = %q, want it to say the response was not understood", dec.Reason)
				}
			})
		}
	}
}

func TestEnforcerClient_FailOpenStillAllowsInfrastructureFailures(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		srv := makeEnforcerServer(t, thoth.DecisionBlock, "x", status)
		client := thoth.NewEnforcerClient(srv.URL, "", true)
		dec, err := client.Check(context.Background(), thoth.CheckRequest{ToolName: "tool", SessionID: "s"})
		srv.Close()
		if err != nil || dec.Decision != thoth.DecisionAllow {
			t.Errorf("status %d: dec=%q err=%v, want ALLOW", status, dec.Decision, err)
		}
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	client := thoth.NewEnforcerClient(slow.URL, "", true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	dec, err := client.Check(ctx, thoth.CheckRequest{ToolName: "tool", SessionID: "s"})
	if err != nil || dec.Decision != thoth.DecisionAllow {
		t.Errorf("timeout: dec=%q err=%v, want ALLOW", dec.Decision, err)
	}
}
