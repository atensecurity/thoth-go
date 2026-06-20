package compat_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	langsmith "github.com/langchain-ai/langsmith-go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	ddtracer "gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

	sdk "github.com/atensecurity/thoth-go"
)

const enforcePath = "/v1/enforce"

type enforcerResponse struct {
	Decision    string `json:"decision,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ViolationID string `json:"violation_id,omitempty"`
}

type runtimeStack string

const (
	stackDatadog       runtimeStack = "datadog"
	stackLangSmith     runtimeStack = "langsmith"
	stackOpenTelemetry runtimeStack = "opentelemetry"
	stackSentry        runtimeStack = "sentry"
)

func selectedStacks() []runtimeStack {
	all := []runtimeStack{
		stackDatadog,
		stackLangSmith,
		stackOpenTelemetry,
		stackSentry,
	}
	filter := os.Getenv("THOTH_COMPAT_STACK")
	if filter == "" {
		return all
	}
	return []runtimeStack{runtimeStack(filter)}
}

func mockEnforcer(t *testing.T, resp enforcerResponse, hitCounter *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == enforcePath {
			atomic.AddInt32(hitCounter, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("mockEnforcer: encode response: %v", err)
		}
	}))
}

func newTestClient(t *testing.T, apiURL string) *sdk.Client {
	t.Helper()
	client, err := sdk.NewClient(sdk.Config{
		APIURL:   apiURL,
		APIKey:   "test-key",
		TenantID: "test-tenant",
		AgentID:  "test-agent",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

type toolFn func(context.Context, string) (string, error)

type noopSentryTransport struct{}

func (n *noopSentryTransport) Flush(timeout time.Duration) bool { return true }
func (n *noopSentryTransport) FlushWithContext(ctx context.Context) bool {
	return true
}
func (n *noopSentryTransport) Configure(options sentry.ClientOptions) {}
func (n *noopSentryTransport) SendEvent(event *sentry.Event)          {}
func (n *noopSentryTransport) Close()                                 {}

func wrapRuntime(
	t *testing.T,
	stack runtimeStack,
	events *[]string,
	next toolFn,
) (toolFn, func()) {
	t.Helper()
	switch stack {
	case stackDatadog:
		ddtracer.Start(
			ddtracer.WithService("thoth-compat"),
			ddtracer.WithAgentAddr("127.0.0.1:9"),
			ddtracer.WithDebugMode(false),
		)
		cleanup := func() { ddtracer.Stop() }
		wrapped := func(ctx context.Context, input string) (string, error) {
			span, innerCtx := ddtracer.StartSpanFromContext(ctx, "search_tool")
			defer span.Finish()
			*events = append(*events, "datadog:run")
			return next(innerCtx, input)
		}
		return wrapped, cleanup
	case stackLangSmith:
		tracer, err := langsmith.NewOTelTracer(
			langsmith.WithAPIKey("test-key"),
			langsmith.WithEndpoint("http://127.0.0.1:9"),
			langsmith.WithProjectName("thoth-compat"),
			langsmith.WithServiceName("thoth-compat"),
			langsmith.WithBatchTimeout(10*time.Millisecond),
		)
		if err != nil {
			t.Fatalf("langsmith tracer init failed: %v", err)
		}
		cleanup := func() {
			_ = tracer.Shutdown(context.Background())
		}
		otelTracer := tracer.Tracer("thoth-compat")
		wrapped := func(ctx context.Context, input string) (string, error) {
			innerCtx, span := otelTracer.Start(ctx, "search_tool")
			defer span.End()
			*events = append(*events, "langsmith:run")
			return next(innerCtx, input)
		}
		return wrapped, cleanup
	case stackOpenTelemetry:
		provider := sdktrace.NewTracerProvider()
		previous := otel.GetTracerProvider()
		otel.SetTracerProvider(provider)
		cleanup := func() {
			_ = provider.Shutdown(context.Background())
			otel.SetTracerProvider(previous)
		}
		otelTracer := otel.Tracer("thoth-compat")
		wrapped := func(ctx context.Context, input string) (string, error) {
			innerCtx, span := otelTracer.Start(ctx, "search_tool")
			defer span.End()
			*events = append(*events, "opentelemetry:run")
			return next(innerCtx, input)
		}
		return wrapped, cleanup
	case stackSentry:
		transport := &noopSentryTransport{}
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              "https://public@example.com/1",
			EnableTracing:    true,
			TracesSampleRate: 1.0,
			Transport:        transport,
		}); err != nil {
			t.Fatalf("sentry init failed: %v", err)
		}
		cleanup := func() {
			sentry.Flush(20 * time.Millisecond)
		}
		wrapped := func(ctx context.Context, input string) (string, error) {
			span := sentry.StartSpan(ctx, "search_tool")
			defer span.Finish()
			*events = append(*events, "sentry:run")
			return next(ctx, input)
		}
		return wrapped, cleanup
	default:
		t.Fatalf("unknown runtime stack: %q", stack)
		return nil, func() {}
	}
}

func TestRuntimeObservabilityAndThothCoexistAllow(t *testing.T) {
	stacks := selectedStacks()
	var enforceHits int32

	srv := mockEnforcer(t, enforcerResponse{Decision: "ALLOW"}, &enforceHits)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	for _, stack := range stacks {
		stack := stack
		t.Run(string(stack)+"/thoth_outer", func(t *testing.T) {
			called := false
			events := []string{}

			base := func(_ context.Context, input string) (string, error) {
				called = true
				events = append(events, "tool:run")
				return "ok:" + input, nil
			}

			runtimeWrapped, cleanup := wrapRuntime(t, stack, &events, base)
			defer cleanup()

			instrumented := client.WrapTool("search_docs", runtimeWrapped)
			out, err := instrumented(context.Background(), "incident 42")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out != "ok:incident 42" {
				t.Fatalf("out = %q, want %q", out, "ok:incident 42")
			}
			if !called {
				t.Fatal("expected wrapped tool to run")
			}
		})

		t.Run(string(stack)+"/thoth_inner", func(t *testing.T) {
			called := false
			events := []string{}

			base := func(_ context.Context, input string) (string, error) {
				called = true
				events = append(events, "tool:run")
				return "ok:" + input, nil
			}

			instrumented := client.WrapTool("search_docs", base)
			runtimeWrapped, cleanup := wrapRuntime(t, stack, &events, instrumented)
			defer cleanup()

			out, err := runtimeWrapped(context.Background(), "incident 42")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out != "ok:incident 42" {
				t.Fatalf("out = %q, want %q", out, "ok:incident 42")
			}
			if !called {
				t.Fatal("expected wrapped tool to run")
			}
		})
	}

	if atomic.LoadInt32(&enforceHits) != int32(len(stacks)*2) {
		t.Fatalf("enforce hits = %d, want %d", enforceHits, len(stacks)*2)
	}
}

func TestRuntimeObservabilityAndThothCoexistBlock(t *testing.T) {
	stacks := selectedStacks()
	var enforceHits int32

	srv := mockEnforcer(t, enforcerResponse{
		Decision:    "BLOCK",
		Reason:      "blocked by policy",
		ViolationID: "vio-runtime-compat-001",
	}, &enforceHits)
	defer srv.Close()

	client := newTestClient(t, srv.URL)

	for _, stack := range stacks {
		stack := stack
		t.Run(string(stack)+"/thoth_outer", func(t *testing.T) {
			called := false
			events := []string{}

			base := func(_ context.Context, input string) (string, error) {
				called = true
				events = append(events, "tool:run")
				return "ok:" + input, nil
			}

			runtimeWrapped, cleanup := wrapRuntime(t, stack, &events, base)
			defer cleanup()

			instrumented := client.WrapTool("delete_record", runtimeWrapped)
			_, err := instrumented(context.Background(), "secret")
			if err == nil {
				t.Fatal("expected block error")
			}
			var pve *sdk.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("expected *PolicyViolationError, got %T: %v", err, err)
			}
			if called {
				t.Fatal("tool should not execute on BLOCK")
			}
			if len(events) != 0 {
				t.Fatalf("events = %v, expected no runtime event when thoth wraps outside", events)
			}
		})

		t.Run(string(stack)+"/thoth_inner", func(t *testing.T) {
			called := false
			events := []string{}

			base := func(_ context.Context, input string) (string, error) {
				called = true
				events = append(events, "tool:run")
				return "ok:" + input, nil
			}

			instrumented := client.WrapTool("delete_record", base)
			runtimeWrapped, cleanup := wrapRuntime(t, stack, &events, instrumented)
			defer cleanup()

			_, err := runtimeWrapped(context.Background(), "secret")
			if err == nil {
				t.Fatal("expected block error")
			}
			var pve *sdk.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("expected *PolicyViolationError, got %T: %v", err, err)
			}
			if called {
				t.Fatal("tool should not execute on BLOCK")
			}
			if len(events) == 0 {
				t.Fatal("expected runtime instrumentation to observe failed call path")
			}
		})
	}

	if atomic.LoadInt32(&enforceHits) != int32(len(stacks)*2) {
		t.Fatalf("enforce hits = %d, want %d", enforceHits, len(stacks)*2)
	}
}
