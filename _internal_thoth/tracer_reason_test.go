package thoth_test

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

func wrappedCall(t *testing.T, url string, failOpen bool, mode thoth.EnforcementMode, args map[string]any) (ran bool, err error) {
	t.Helper()
	cfg := thoth.ApplyConfigDefaults(thoth.Config{
		AgentID: "a", TenantID: "t", Enforcement: mode, EnforcerURL: url, FailOpen: failOpen,
	})
	tracer := thoth.NewTracer(cfg, thoth.NewSessionContext(cfg), nil)
	fn := func(ctx context.Context, a ...any) (any, error) { ran = true; return "ok", nil }
	_, err = tracer.WrapTool("some_tool", fn)(context.Background(), args)
	return ran, err
}

// The reason the caller of a wrapped tool sees is the client's specific reason, in both
// fail-open modes, and the tool never runs.
func TestWrapTool_CallerSeesSpecificBlockReason(t *testing.T) {
	t.Parallel()
	status := func(code int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`<html>`)) }))
	defer garbage.Close()
	forbidden := status(http.StatusForbidden)
	defer forbidden.Close()
	cases := []struct {
		name string
		url  string
		args map[string]any
		want string
	}{
		{"request not built", garbage.URL, map[string]any{"v": math.NaN()}, "request could not be built"},
		{"not understood", garbage.URL, nil, "enforcer response not understood"},
		{"rejected", forbidden.URL, nil, "enforcer rejected request (status=403)"},
	}
	for _, tc := range cases {
		for _, failOpen := range []bool{true, false} {
			ran, err := wrappedCall(t, tc.url, failOpen, thoth.Block, tc.args)
			var pve *thoth.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("%s failOpen=%v: err = %v, want PolicyViolationError", tc.name, failOpen, err)
			}
			if pve.Reason != tc.want {
				t.Errorf("%s failOpen=%v: reason %q, want %q", tc.name, failOpen, pve.Reason, tc.want)
			}
			if ran {
				t.Errorf("%s failOpen=%v: tool ran", tc.name, failOpen)
			}
		}
	}
}

// Safety: outages with fail-open on still allow exactly as before; with it off they block
// with the generic reason family. Observe mode never blocks.
func TestWrapTool_ReasonChangeNeverTurnsOutageIntoDifferentOutcome(t *testing.T) {
	t.Parallel()
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		code := code
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		ran, err := wrappedCall(t, srv.URL, true, thoth.Block, nil)
		if err != nil || !ran {
			t.Errorf("status %d fail-open: ran=%v err=%v, want the tool to run", code, ran, err)
		}
		ran, err = wrappedCall(t, srv.URL, false, thoth.Block, nil)
		var pve *thoth.PolicyViolationError
		if !errors.As(err, &pve) || ran {
			t.Errorf("status %d fail-closed: ran=%v err=%v, want blocked", code, ran, err)
		}
		srv.Close()
	}
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`x`)) }))
	defer garbage.Close()
	for _, failOpen := range []bool{true, false} {
		ran, err := wrappedCall(t, garbage.URL, failOpen, thoth.Observe, nil)
		if err != nil || !ran {
			t.Errorf("observe failOpen=%v: ran=%v err=%v, want the tool to run", failOpen, ran, err)
		}
	}
}
