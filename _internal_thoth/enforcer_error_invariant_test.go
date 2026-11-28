package thoth_test

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	thoth "github.com/atensecurity/thoth-go/_internal_thoth"
)

// The tracer keeps the client's decision on error only when it is a BLOCK with a reason.
// That is safe because the client never pairs an error with anything but BLOCK: pin it.
func TestEnforcerClient_ErrorAlwaysComesWithBlockAndReason(t *testing.T) {
	t.Parallel()
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closed.Close()
	urls := map[string]string{"closed": closed.URL}
	for name, h := range map[string]http.HandlerFunc{
		"503":     func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) },
		"429":     func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) },
		"403":     func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) },
		"garbage": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) },
		"null":    func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("null")) },
		"broken":  brokenBody,
	} {
		srv := httptest.NewServer(h)
		defer srv.Close()
		urls[name] = srv.URL
	}
	for name, url := range urls {
		for _, failOpen := range []bool{true, false} {
			dec, err := thoth.NewEnforcerClient(url, "", failOpen).Check(context.Background(), thoth.CheckRequest{ToolName: "t", SessionID: "s"})
			if err != nil && (dec.Decision != thoth.DecisionBlock || dec.Reason == "") {
				t.Errorf("%s failOpen=%v: error with %q %q", name, failOpen, dec.Decision, dec.Reason)
			}
		}
	}
}

// Local error paths: each blocks with a specific reason in both modes.
func TestEnforcerClient_LocalErrorPathsBlockWithSpecificReason(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"decision":"ALLOW"}`)) }))
	defer srv.Close()
	cases := map[string]struct {
		url  string
		args map[string]any
	}{
		"nan args":      {srv.URL, map[string]any{"x": math.NaN()}},
		"over 4 MiB":    {srv.URL, map[string]any{"x": strings.Repeat("a", thoth.MaxRequestBytes+1)}},
		"request build": {"http://bad\x7fhost", nil},
	}
	for name, tc := range cases {
		for _, failOpen := range []bool{true, false} {
			dec, err := thoth.NewEnforcerClient(tc.url, "", failOpen).Check(context.Background(),
				thoth.CheckRequest{ToolName: "t", SessionID: "s", ToolArgs: tc.args})
			if err == nil || dec.Decision != thoth.DecisionBlock || dec.Reason == "" || dec.Reason == "enforcer unavailable" {
				t.Errorf("%s failOpen=%v: %q %q %v", name, failOpen, dec.Decision, dec.Reason, err)
			}
		}
	}
}
