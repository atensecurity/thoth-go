package thoth

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Not parallel: it lowers a package variable.
func TestEnforcerResponseOverLimitBlocksInBothModes(t *testing.T) {
	prev := maxResponseBytes
	maxResponseBytes = 1024
	defer func() { maxResponseBytes = prev }()

	var written atomic.Int64
	const streamCap = 32 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat(" ", 1024))
		for written.Load() < streamCap {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	for _, failOpen := range []bool{true, false} {
		written.Store(0)
		dec, err := NewEnforcerClient(srv.URL, "", failOpen).Check(context.Background(), CheckRequest{ToolName: "t", SessionID: "s"})
		if err == nil || dec.Decision != DecisionBlock || dec.Reason != "enforcer response not understood" {
			t.Fatalf("failOpen=%v: %q %q %v", failOpen, dec.Decision, dec.Reason, err)
		}
		if written.Load() >= streamCap {
			t.Errorf("failOpen=%v: server wrote the whole stream; the read did not stop near the limit", failOpen)
		}
	}
}

func TestEnforcerResponseExactlyAtLimitStillParses(t *testing.T) {
	body := `{"decision":"ALLOW"}`
	prev := maxResponseBytes
	maxResponseBytes = int64(len(body))
	defer func() { maxResponseBytes = prev }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	dec, err := NewEnforcerClient(srv.URL, "", false).Check(context.Background(), CheckRequest{ToolName: "t", SessionID: "s"})
	if err != nil || dec.Decision != DecisionAllow {
		t.Fatalf("%q %v, want ALLOW", dec.Decision, err)
	}
}

func TestEnforcerUnavailableReasonCarriesStatusWhenFailClosed(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		status := status
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		dec, _ := NewEnforcerClient(srv.URL, "", false).Check(context.Background(), CheckRequest{ToolName: "t", SessionID: "s"})
		srv.Close()
		want := "enforcer unavailable (status=" + strconv.Itoa(status) + ")"
		if dec.Decision != DecisionBlock || dec.Reason != want {
			t.Errorf("status %d: %q %q, want %q", status, dec.Decision, dec.Reason, want)
		}
	}
}

// Not parallel: it redirects the standard logger.
func TestObserveLogsRequestNotBuiltReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"decision":"ALLOW"}`)) }))
	defer srv.Close()
	cfg := ApplyConfigDefaults(Config{AgentID: "a", TenantID: "t", Enforcement: Observe, EnforcerURL: srv.URL})
	tracer := NewTracer(cfg, NewSessionContext(cfg), nil)
	var buf bytes.Buffer
	restore := captureLog(&buf)
	_, _ = tracer.WrapTool("x", func(ctx context.Context, args ...any) (any, error) { return nil, nil })(context.Background(), map[string]any{"v": math.NaN()})
	restore()
	if !strings.Contains(buf.String(), "request could not be built") || strings.Contains(buf.String(), "enforcer unavailable") {
		t.Errorf("observe log: %q", buf.String())
	}
}

// Valid JSON padded with whitespace past the cap decodes fine, so only the explicit
// size check can block it.
func TestEnforcerResponsePaddedPastLimitBlocksInBothModes(t *testing.T) {
	prev := maxResponseBytes
	maxResponseBytes = 1024
	defer func() { maxResponseBytes = prev }()
	body := `{"decision":"ALLOW"}` + strings.Repeat(" ", 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer srv.Close()
	for _, failOpen := range []bool{true, false} {
		dec, err := NewEnforcerClient(srv.URL, "", failOpen).Check(context.Background(), CheckRequest{ToolName: "t", SessionID: "s"})
		if err == nil || dec.Decision != DecisionBlock || dec.Reason != "enforcer response not understood" {
			t.Errorf("failOpen=%v: %q %q %v", failOpen, dec.Decision, dec.Reason, err)
		}
	}
}
