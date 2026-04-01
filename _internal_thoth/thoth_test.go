package thoth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atensecurity/thoth-go/_internal_thoth"
)

// testAgent has exported methods that match ToolFunc and one that doesn't.
type testAgent struct {
	calls []string
}

func (a *testAgent) ReadInvoices(ctx context.Context, args ...any) (any, error) {
	a.calls = append(a.calls, "ReadInvoices")
	return "invoice-data", nil
}

func (a *testAgent) WriteSlack(ctx context.Context, args ...any) (any, error) {
	a.calls = append(a.calls, "WriteSlack")
	return "sent", nil
}

// NotAToolFunc has the wrong signature and must NOT be wrapped.
func (a *testAgent) NotAToolFunc(name string) string {
	return name
}

func TestInstrument_RegistersWrappedTools(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
	}))
	defer srv.Close()

	agent := &testAgent{}
	cfg := thoth.Config{
		AgentID:       "test-agent",
		TenantID:      "t",
		ApprovedScope: []string{"ReadInvoices", "WriteSlack"},
		Enforcement:   thoth.Block,
		EnforcerURL:   srv.URL,
	}

	tracer := thoth.Instrument(agent, cfg)
	if tracer == nil {
		t.Fatal("Instrument returned nil tracer")
	}

	// Both ToolFunc-compatible methods must be registered; NotAToolFunc must not be.
	names := tracer.ToolNames()
	if len(names) != 2 {
		t.Errorf("expected 2 registered tools, got %d: %v", len(names), names)
	}

	// Invoking a registered tool through the tracer must execute the underlying method
	// and return its result.
	result, err := tracer.Call(context.Background(), "ReadInvoices")
	if err != nil {
		t.Fatalf("Call(ReadInvoices) error: %v", err)
	}
	if result != "invoice-data" {
		t.Errorf("unexpected result: %v", result)
	}
	if len(agent.calls) != 1 || agent.calls[0] != "ReadInvoices" {
		t.Errorf("underlying method not called; agent.calls=%v", agent.calls)
	}
}

func TestInstrument_NilAgent_ReturnsEmptyTracer(t *testing.T) {
	t.Parallel()
	tracer := thoth.Instrument(nil, thoth.Config{AgentID: "a", TenantID: "t"})
	if tracer == nil {
		t.Fatal("Instrument(nil) returned nil tracer")
	}
	if len(tracer.ToolNames()) != 0 {
		t.Errorf("expected empty tool registry for nil agent, got %v", tracer.ToolNames())
	}
}

func TestInstrument_NoWrappableTools_EmptyRegistry(t *testing.T) {
	t.Parallel()
	type noTools struct{ X int }
	tracer := thoth.Instrument(&noTools{X: 42}, thoth.Config{AgentID: "a", TenantID: "t"})
	if tracer == nil {
		t.Fatal("Instrument returned nil tracer")
	}
	if len(tracer.ToolNames()) != 0 {
		t.Errorf("expected empty registry, got %v", tracer.ToolNames())
	}
}

func TestInstrument_CallUnregisteredTool_ReturnsError(t *testing.T) {
	t.Parallel()
	tracer := thoth.Instrument(nil, thoth.Config{AgentID: "a", TenantID: "t"})
	_, err := tracer.Call(context.Background(), "ghost_tool")
	if err == nil {
		t.Fatal("expected error calling unregistered tool, got nil")
	}
}

func TestInstrument_BlockedTool_ReturnsPolicyViolationError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"BLOCK","reason":"out of scope"}`))
	}))
	defer srv.Close()

	agent := &testAgent{}
	cfg := thoth.Config{
		AgentID:     "test-agent",
		TenantID:    "t",
		Enforcement: thoth.Block,
		EnforcerURL: srv.URL,
	}

	tracer := thoth.Instrument(agent, cfg)
	_, err := tracer.Call(context.Background(), "WriteSlack")
	if err == nil {
		t.Fatal("expected PolicyViolationError, got nil")
	}
	var pve *thoth.PolicyViolationError
	if !errors.As(err, &pve) {
		t.Errorf("expected *PolicyViolationError, got %T: %v", err, err)
	}
}

func TestToolFunc_Signature(t *testing.T) {
	t.Parallel()
	// Verify that a plain ToolFunc can be wrapped directly via WrapTool.
	fn := thoth.ToolFunc(func(ctx context.Context, args ...any) (any, error) {
		return "direct", nil
	})
	result, err := fn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result != "direct" {
		t.Errorf("result = %v", result)
	}
}
