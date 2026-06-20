package thoth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	sdk "github.com/atensecurity/thoth-go"
)

type compatToolFunc func(context.Context, string) (string, error)

func wrapObservabilityLike(
	stack string,
	events *[]string,
	next compatToolFunc,
) compatToolFunc {
	return func(ctx context.Context, input string) (string, error) {
		*events = append(*events, stack+":start")
		out, err := next(ctx, input)
		if err != nil {
			*events = append(*events, stack+":error")
			return "", err
		}
		*events = append(*events, stack+":end")
		return out, nil
	}
}

func makeBaseTool(events *[]string, called *bool) compatToolFunc {
	return func(_ context.Context, input string) (string, error) {
		*called = true
		*events = append(*events, "tool:run")
		return "ok:" + input, nil
	}
}

func TestWrapTool_ObservabilityWrapperCoexistsOnAllow(t *testing.T) {
	stacks := []string{"datadog", "langsmith", "opentelemetry", "sentry"}

	var enforceHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == enforcePath {
			atomic.AddInt32(&enforceHits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{Decision: "ALLOW"})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	for _, stack := range stacks {
		t.Run(stack+"/thoth_outer", func(t *testing.T) {
			called := false
			events := []string{}
			base := makeBaseTool(&events, &called)
			inside := wrapObservabilityLike(stack, &events, base)
			instrumented := client.WrapTool("search_docs", inside)

			out, err := instrumented(context.Background(), "incident 42")
			if err != nil {
				t.Fatalf("thoth_outer unexpected error: %v", err)
			}
			if out != "ok:incident 42" {
				t.Fatalf("thoth_outer out = %q, want %q", out, "ok:incident 42")
			}
			if !called {
				t.Fatal("thoth_outer expected underlying tool to run")
			}
			want := []string{stack + ":start", "tool:run", stack + ":end"}
			if len(events) != len(want) {
				t.Fatalf("thoth_outer events = %v, want %v", events, want)
			}
			for i := range want {
				if events[i] != want[i] {
					t.Fatalf("thoth_outer events[%d] = %q, want %q", i, events[i], want[i])
				}
			}
		})

		t.Run(stack+"/thoth_inner", func(t *testing.T) {
			called := false
			events := []string{}
			base := makeBaseTool(&events, &called)
			instrumented := client.WrapTool("search_docs", base)
			outside := wrapObservabilityLike(stack, &events, instrumented)

			out, err := outside(context.Background(), "incident 42")
			if err != nil {
				t.Fatalf("thoth_inner unexpected error: %v", err)
			}
			if out != "ok:incident 42" {
				t.Fatalf("thoth_inner out = %q, want %q", out, "ok:incident 42")
			}
			if !called {
				t.Fatal("thoth_inner expected underlying tool to run")
			}
			want := []string{stack + ":start", "tool:run", stack + ":end"}
			if len(events) != len(want) {
				t.Fatalf("thoth_inner events = %v, want %v", events, want)
			}
			for i := range want {
				if events[i] != want[i] {
					t.Fatalf("thoth_inner events[%d] = %q, want %q", i, events[i], want[i])
				}
			}
		})
	}

	if atomic.LoadInt32(&enforceHits) != int32(len(stacks)*2) {
		t.Fatalf("enforce hits = %d, want %d", enforceHits, len(stacks)*2)
	}
}

func TestWrapTool_ObservabilityWrapperCoexistsOnBlock(t *testing.T) {
	stacks := []string{"datadog", "langsmith", "opentelemetry", "sentry"}

	var enforceHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == enforcePath {
			atomic.AddInt32(&enforceHits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enforcerResponse{
			Decision:    "BLOCK",
			Reason:      "blocked by policy",
			ViolationID: "vio-compat-001",
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	for _, stack := range stacks {
		t.Run(stack+"/thoth_outer", func(t *testing.T) {
			called := false
			events := []string{}
			base := makeBaseTool(&events, &called)
			inside := wrapObservabilityLike(stack, &events, base)
			instrumented := client.WrapTool("delete_record", inside)

			_, err := instrumented(context.Background(), "secret")
			if err == nil {
				t.Fatal("thoth_outer expected error, got nil")
			}
			var pve *sdk.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("thoth_outer expected *PolicyViolationError, got %T: %v", err, err)
			}
			if called {
				t.Fatal("thoth_outer tool should not run on BLOCK")
			}
			if len(events) != 0 {
				t.Fatalf("thoth_outer events = %v, want none", events)
			}
		})

		t.Run(stack+"/thoth_inner", func(t *testing.T) {
			called := false
			events := []string{}
			base := makeBaseTool(&events, &called)
			instrumented := client.WrapTool("delete_record", base)
			outside := wrapObservabilityLike(stack, &events, instrumented)

			_, err := outside(context.Background(), "secret")
			if err == nil {
				t.Fatal("thoth_inner expected error, got nil")
			}
			var pve *sdk.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("thoth_inner expected *PolicyViolationError, got %T: %v", err, err)
			}
			if called {
				t.Fatal("thoth_inner tool should not run on BLOCK")
			}
			want := []string{stack + ":start", stack + ":error"}
			if len(events) != len(want) {
				t.Fatalf("thoth_inner events = %v, want %v", events, want)
			}
			for i := range want {
				if events[i] != want[i] {
					t.Fatalf("thoth_inner events[%d] = %q, want %q", i, events[i], want[i])
				}
			}
		})
	}

	if atomic.LoadInt32(&enforceHits) != int32(len(stacks)*2) {
		t.Fatalf("enforce hits = %d, want %d", enforceHits, len(stacks)*2)
	}
}
