package thoth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/atensecurity/thoth-go"
)

const dhCanary = "CANARY-9f3a-secret-value"

type dhRequest struct {
	Path string
	Raw  string
	Body map[string]any
}

// dhServer records every request body and answers /v1/enforce with the given
// response and the hold poll with an approval.
type dhServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []dhRequest
}

func newDHServer(t *testing.T, enforce map[string]any) *dhServer {
	t.Helper()
	s := &dhServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		s.mu.Lock()
		s.requests = append(s.requests, dhRequest{r.URL.Path, string(raw), body})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/enforce":
			_ = json.NewEncoder(w).Encode(enforce)
		case strings.HasPrefix(r.URL.Path, "/v1/enforce/hold/"):
			_, _ = w.Write([]byte(`{"resolved":true,"resolution":"ALLOW"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *dhServer) enforceBodies() []dhRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []dhRequest
	for _, r := range s.requests {
		if r.Path == "/v1/enforce" {
			out = append(out, r)
		}
	}
	return out
}

func (s *dhServer) everything() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []string
	for _, r := range s.requests {
		all = append(all, r.Raw)
	}
	return strings.Join(all, "\n")
}

func dhClient(t *testing.T, url string, mutate func(*sdk.Config)) *sdk.Client {
	t.Helper()
	for _, name := range []string{"THOTH_DATA_HANDLING_TOOL_ARGUMENTS", "THOTH_DATA_HANDLING_PROMPTS", "THOTH_DATA_HANDLING_SALT", "THOTH_DATA_HANDLING_LOCAL_SCAN"} {
		t.Setenv(name, "")
	}
	cfg := sdk.Config{APIURL: url, APIKey: "test-key", TenantID: "test-tenant", AgentID: "test-agent", Timeout: 2 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := sdk.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(client.Close)
	return client
}

func dhArgs() map[string]any {
	return map[string]any{
		"path":   "/data/patient_records.csv",
		"note":   "ssn 123-45-6789 " + dhCanary,
		"to":     "alice@corp.example.com",
		"url":    "https://exfil.example.net/upload",
		"nested": map[string]any{"count": 3, "flag": true, "none": nil},
	}
}

func callSend(t *testing.T, client *sdk.Client, args map[string]any) (map[string]any, bool, error) {
	t.Helper()
	var got map[string]any
	ran := false
	send := client.WrapToolFunc("send_email", func(_ context.Context, a map[string]any) (any, error) {
		ran, got = true, a
		return "sent", nil
	})
	_, err := send(context.Background(), args)
	return got, ran, err
}

func TestDataHandlingUnsetChangesNothing(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, nil)
	if _, ran, err := callSend(t, client, dhArgs()); err != nil || !ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	body := srv.enforceBodies()[0].Body
	if _, ok := body["data_handling"]; ok {
		t.Error("data_handling must be absent when nothing is configured")
	}
	if _, ok := body["client_findings"]; ok {
		t.Error("client_findings must be absent when nothing is configured")
	}
	args := body["tool_args"].(map[string]any)
	if args["note"] != "ssn 123-45-6789 "+dhCanary || args["path"] != "/data/patient_records.csv" {
		t.Errorf("arguments must be sent as before: %v", args)
	}
}

func TestHashSendsKeyedHashesAndKeepsStructure(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) {
		c.DataHandlingToolArguments = "hash"
		c.DataHandlingSalt = "golden-salt-v1"
	})
	got, ran, err := callSend(t, client, dhArgs())
	if err != nil || !ran || got["note"] != "ssn 123-45-6789 "+dhCanary {
		t.Fatalf("the tool must run with the original arguments: ran=%v err=%v got=%v", ran, err, got)
	}
	body := srv.enforceBodies()[0].Body
	args := body["tool_args"].(map[string]any)
	if !strings.HasPrefix(args["to"].(string), "hmac-sha256:") || len(args["to"].(string)) != len("hmac-sha256:")+64 {
		t.Errorf("to = %v", args["to"])
	}
	nested := args["nested"].(map[string]any)
	if nested["none"] != nil || !strings.HasPrefix(nested["count"].(string), "hmac-sha256:") || !strings.HasPrefix(nested["flag"].(string), "hmac-sha256:") {
		t.Errorf("nested = %v", nested)
	}
	if body["data_handling"].(map[string]any)["tool_arguments"] != "hash" {
		t.Errorf("data_handling = %v", body["data_handling"])
	}
	// The salt and the values never leave the process, on any request.
	all := srv.everything()
	for _, leaked := range []string{"CANARY", "123-45-6789", "alice@", "golden-salt-v1", "/data/patient_records.csv"} {
		if strings.Contains(all, leaked) {
			t.Errorf("%q reached the server: %s", leaked, all)
		}
	}
}

// The same bytes the Python and TypeScript SDKs send (the shared golden fixture).
func TestHashMatchesTheSharedGoldenOnTheWire(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) {
		c.DataHandlingToolArguments = "hash"
		c.DataHandlingSalt = "golden-salt-v1"
	})
	_, _, _ = callSend(t, client, map[string]any{"to": "alice@example.com", "subject": "Quarterly numbers"})
	args := srv.enforceBodies()[0].Body["tool_args"].(map[string]any)
	if args["to"] != "hmac-sha256:bf8a0dc3bf9ec6f1c64cbe369d94579e29bdbf1660639992118b01257ddb0c4d" ||
		args["subject"] != "hmac-sha256:a13d80d25159fa07fdb7141e151d32365d6834d98d8fcfd8dee766ffb8154f65" {
		t.Errorf("%v", args)
	}
}

func TestRedactKeepsKeysAndDropSendsNoArguments(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "redact" })
	_, _, _ = callSend(t, client, dhArgs())
	args := srv.enforceBodies()[0].Body["tool_args"].(map[string]any)
	if args["note"] != "<redacted>" || args["nested"].(map[string]any)["none"] != "<redacted>" || len(args) != 5 {
		t.Errorf("%v", args)
	}
	if strings.Contains(srv.enforceBodies()[0].Raw, "CANARY") {
		t.Error("redact leaked")
	}

	dropSrv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	dropClient := dhClient(t, dropSrv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "drop" })
	_, ran, err := callSend(t, dropClient, dhArgs())
	if err != nil || !ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	body := dropSrv.enforceBodies()[0]
	if _, ok := body.Body["tool_args"]; ok {
		t.Error("drop sends no tool_args")
	}
	if body.Body["data_handling"].(map[string]any)["tool_arguments"] != "drop" || strings.Contains(dropSrv.everything(), "CANARY") {
		t.Errorf("%v", body.Body["data_handling"])
	}
}

func TestPositionalArgumentsAreWithheldToo(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "hash" })
	echo := client.WrapTool("echo", func(_ context.Context, input string) (string, error) { return input, nil })
	out, err := echo(context.Background(), "ssn 123-45-6789 "+dhCanary)
	if err != nil || out != "ssn 123-45-6789 "+dhCanary {
		t.Fatalf("%q %v", out, err)
	}
	body := srv.enforceBodies()[0].Body
	if !strings.HasPrefix(body["tool_args"].(map[string]any)["arg0"].(string), "hmac-sha256:") || strings.Contains(srv.everything(), "CANARY") {
		t.Errorf("%v", body["tool_args"])
	}
	findings := body["client_findings"].(map[string]any)["findings"]
	if !strings.Contains(asJSON(t, findings), `"category":"ssn"`) {
		t.Errorf("the scan reads arg0: %v", findings)
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestClientFindingsOnTheWire(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) {
		c.DataHandlingToolArguments = "hash"
		c.RequestMetadata = map[string]any{"target_host": "https://Broker.Example.org:8443/x"}
	})
	_, _, _ = callSend(t, client, dhArgs())
	body := srv.enforceBodies()[0].Body
	report := body["client_findings"].(map[string]any)
	scanner := report["scanner"].(map[string]any)
	if scanner["name"] != "atensec-thoth-go" || scanner["ruleset_id"] != "thoth-detectors.v1" ||
		scanner["ruleset_hash"] != "db797fde60f300719b9dac8a360efd6ce8b1f7313587cc714aebf7a93428434b" || scanner["version"] == "" {
		t.Errorf("scanner = %v", scanner)
	}
	if report["version"] != float64(1) || asJSON(t, report["scanned"]) != `["dlp","sensitive_path","egress_host","recipient"]` {
		t.Errorf("report = %v", report)
	}
	text := asJSON(t, report["findings"])
	// Counts, categories, a hostname from the request metadata and recipient domains; the request
	// metadata's destination comes before the arguments' url.
	for _, want := range []string{`"category":"ssn"`, `"category":"email"`, `"host":"broker.example.org"`, `"domains":["corp.example.com"]`, `"kind":"sensitive_path"`} {
		if !strings.Contains(text, want) {
			t.Errorf("findings lack %s: %s", want, text)
		}
	}
	for _, leaked := range []string{"alice", "CANARY", "patient_records", "123-45", "exfil", "upload", "8443"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(leaked)) {
			t.Errorf("findings leak %q: %s", leaked, text)
		}
	}
	if len(srv.enforceBodies()[0].Raw) < 100 {
		t.Fatal("empty body")
	}
}

func TestLocalScanOffSwitch(t *testing.T) {
	for name, set := range map[string]func(*testing.T, *sdk.Config){
		"option": func(_ *testing.T, c *sdk.Config) { c.DataHandlingLocalScan = "off" },
		"env":    func(t *testing.T, _ *sdk.Config) { t.Setenv("THOTH_DATA_HANDLING_LOCAL_SCAN", "off") },
	} {
		t.Run(name, func(t *testing.T) {
			srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
			// dhClient clears the environment first, so set it through the mutate hook.
			client := dhClient(t, srv.URL, func(c *sdk.Config) {
				c.DataHandlingToolArguments = "hash"
				set(t, c)
			})
			_, _, _ = callSend(t, client, dhArgs())
			body := srv.enforceBodies()[0].Body
			if _, ok := body["client_findings"]; ok {
				t.Error("local scan off must send no client_findings")
			}
			if body["data_handling"] == nil || strings.Contains(srv.everything(), "CANARY") {
				t.Error("values are still withheld and declared")
			}
		})
	}
}

func TestLocalScanOnlyRunsWhenArgumentsAreWithheld(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingPrompts = "hash" })
	_, _, _ = callSend(t, client, dhArgs())
	body := srv.enforceBodies()[0].Body
	if _, ok := body["client_findings"]; ok {
		t.Error("with only prompts withheld the arguments are sent, and Thoth scans them itself")
	}
	if body["data_handling"].(map[string]any)["prompts"] != "hash" {
		t.Errorf("%v", body["data_handling"])
	}
	if body["tool_args"].(map[string]any)["note"] != "ssn 123-45-6789 "+dhCanary {
		t.Error("arguments are sent when only prompts are withheld")
	}
}

func TestEnvironmentVariablesConfigureDataHandling(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	for _, name := range []string{"THOTH_DATA_HANDLING_PROMPTS", "THOTH_DATA_HANDLING_LOCAL_SCAN"} {
		t.Setenv(name, "")
	}
	t.Setenv("THOTH_DATA_HANDLING_TOOL_ARGUMENTS", "hash")
	t.Setenv("THOTH_DATA_HANDLING_SALT", "fleet-salt")
	client, err := sdk.NewClient(sdk.Config{APIURL: srv.URL, APIKey: "k", TenantID: "t", AgentID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _, _ = callSend(t, client, map[string]any{"to": "alice@example.com"})
	args := srv.enforceBodies()[0].Body["tool_args"].(map[string]any)
	if !strings.HasPrefix(args["to"].(string), "hmac-sha256:") {
		t.Fatalf("%v", args)
	}
	// Same salt in another process gives the same hash.
	other := newDHServer(t, map[string]any{"decision": "ALLOW"})
	second, _ := sdk.NewClient(sdk.Config{APIURL: other.URL, APIKey: "k", TenantID: "t", AgentID: "a"})
	defer second.Close()
	_, _, _ = callSend(t, second, map[string]any{"to": "alice@example.com"})
	if other.enforceBodies()[0].Body["tool_args"].(map[string]any)["to"] != args["to"] {
		t.Error("a shared salt gives matching hashes")
	}
}

func TestInvalidSettingsFailWhenTheClientIsBuilt(t *testing.T) {
	for _, name := range []string{"THOTH_DATA_HANDLING_TOOL_ARGUMENTS", "THOTH_DATA_HANDLING_PROMPTS", "THOTH_DATA_HANDLING_SALT", "THOTH_DATA_HANDLING_LOCAL_SCAN"} {
		t.Setenv(name, "")
	}
	for name, cfg := range map[string]sdk.Config{
		"mode":       {DataHandlingToolArguments: "scramble"},
		"prompts":    {DataHandlingPrompts: "redact"},
		"local scan": {DataHandlingToolArguments: "hash", DataHandlingLocalScan: "sometimes"},
	} {
		cfg.APIURL, cfg.APIKey, cfg.TenantID, cfg.AgentID = "http://127.0.0.1:1", "k", "t", "a"
		if client, err := sdk.NewClient(cfg); err == nil {
			client.Close()
			t.Errorf("%s: expected an error", name)
		}
	}
	t.Setenv("THOTH_DATA_HANDLING_TOOL_ARGUMENTS", "has")
	if client, err := sdk.NewClient(sdk.Config{APIURL: "http://127.0.0.1:1", APIKey: "k", TenantID: "t", AgentID: "a"}); err == nil {
		client.Close()
		t.Error("an invalid environment value must fail")
	}
}

func TestPromptsModeHashesPromptBearingContext(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) {
		c.DataHandlingPrompts = "hash"
		c.DataHandlingSalt = "s"
		c.TaskContext = map[string]any{"task_id": "t-1", "prompt": "summarise " + dhCanary, "nested": map[string]any{"user_message": dhCanary}}
		c.RequestMetadata = map[string]any{"description": dhCanary, "region": "us"}
	})
	_, _, _ = callSend(t, client, map[string]any{"to": "a@x.com"})
	body := srv.enforceBodies()[0].Body
	task := body["task_context"].(map[string]any)
	if task["task_id"] != "t-1" || !strings.HasPrefix(task["prompt"].(string), "hmac-sha256:") ||
		!strings.HasPrefix(task["nested"].(map[string]any)["user_message"].(string), "hmac-sha256:") {
		t.Errorf("task_context = %v", task)
	}
	meta := body["metadata"].(map[string]any)
	if meta["region"] != "us" || !strings.HasPrefix(meta["description"].(string), "hmac-sha256:") {
		t.Errorf("metadata = %v", meta)
	}
	if strings.Contains(srv.everything(), "CANARY") {
		t.Error("a prompt value reached the server")
	}
	if body["data_handling"].(map[string]any)["prompts"] != "hash" {
		t.Errorf("%v", body["data_handling"])
	}
}

// With arguments withheld, a server rewrite would feed placeholders into the tool.
func TestRewriteForWithheldArgumentsFailsClosed(t *testing.T) {
	responses := map[string]map[string]any{
		"decision MODIFY":              {"decision": "MODIFY", "modified_tool_args": map[string]any{"to": "x@y.org"}},
		"ALLOW beside authorization":   {"decision": "ALLOW", "authorization_decision": "MODIFY", "modified_tool_args": map[string]any{"to": "x@y.org"}},
		"MODIFY without arguments":     {"decision": "MODIFY"},
		"approved hold with a rewrite": {"decision": "STEP_UP", "hold_token": "tok-1", "modified_tool_args": map[string]any{"to": "out@example.com", "body": "[REDACTED]"}},
	}
	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			srv := newDHServer(t, response)
			client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "hash" })
			_, ran, err := callSend(t, client, dhArgs())
			var pve *sdk.PolicyViolationError
			if !errors.As(err, &pve) {
				t.Fatalf("expected *PolicyViolationError, got %T: %v", err, err)
			}
			if ran {
				t.Fatal("the tool ran although the server returned an argument rewrite for withheld arguments")
			}
			if !strings.Contains(pve.Reason, "argument rewrite") || !strings.Contains(pve.Reason, "withheld") {
				t.Errorf("reason = %q", pve.Reason)
			}
		})
	}
}

func TestWithoutWithholdingModifyStillApplies(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW", "authorization_decision": "MODIFY", "modified_tool_args": map[string]any{"to": "x@y.org", "body": "[REDACTED]"}})
	client := dhClient(t, srv.URL, nil)
	got, ran, err := callSend(t, client, map[string]any{"to": "out@example.com", "body": "card 4111"})
	if err != nil || !ran || got["body"] != "[REDACTED]" {
		t.Fatalf("ran=%v err=%v got=%v", ran, err, got)
	}
}

func TestApprovedHoldWithoutRewriteRunsWithOriginalArguments(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "STEP_UP", "hold_token": "tok-2", "decision_reason_code": "args_withheld"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "redact" })
	got, ran, err := callSend(t, client, dhArgs())
	if err != nil || !ran || got["note"] != "ssn 123-45-6789 "+dhCanary {
		t.Fatalf("ran=%v err=%v got=%v", ran, err, got)
	}
}

func TestArgsWithheldHoldExplainsItself(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "BLOCK", "reason": "needs review", "decision_reason_code": "args_withheld"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "hash" })
	_, ran, err := callSend(t, client, dhArgs())
	var pve *sdk.PolicyViolationError
	if !errors.As(err, &pve) || ran {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	if !strings.Contains(pve.Reason, "needs review") || !strings.Contains(pve.Reason, "args_withheld") || !strings.Contains(pve.Reason, "THOTH_DATA_HANDLING_TOOL_ARGUMENTS") {
		t.Errorf("reason = %q", pve.Reason)
	}
}

func TestSessionsShareTheClientsDataHandling(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "hash" })
	session, err := client.StartSession(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	send := session.WrapToolFunc("send_email", func(_ context.Context, args map[string]any) (any, error) { return "ok", nil })
	if _, err := send(context.Background(), dhArgs()); err != nil {
		t.Fatal(err)
	}
	body := srv.enforceBodies()[0].Body
	if body["data_handling"] == nil || body["client_findings"] == nil || strings.Contains(srv.everything(), "CANARY") {
		t.Errorf("the session sends raw values or no declaration: %v", body["data_handling"])
	}
}

func TestObserveModeWithholdsToo(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "MODIFY", "modified_tool_args": map[string]any{"to": "x"}})
	client := dhClient(t, srv.URL, func(c *sdk.Config) {
		c.DataHandlingToolArguments = "hash"
		c.Enforcement = "observe"
	})
	got, ran, err := callSend(t, client, dhArgs())
	if err != nil || !ran || got["to"] != "alice@corp.example.com" {
		t.Fatalf("observe always runs the original arguments: ran=%v err=%v got=%v", ran, err, got)
	}
	if strings.Contains(srv.everything(), "CANARY") {
		t.Error("observe leaked")
	}
}

// Telemetry is a minimal projection already; with values withheld it must not
// carry them either, after the emitter has flushed.
func TestTelemetryCarriesNoValuesEither(t *testing.T) {
	srv := newDHServer(t, map[string]any{"decision": "ALLOW"})
	client := dhClient(t, srv.URL, func(c *sdk.Config) { c.DataHandlingToolArguments = "drop" })
	_, _, _ = callSend(t, client, dhArgs())
	client.Close()
	sawEvents := false
	srv.mu.Lock()
	for _, r := range srv.requests {
		if r.Path == "/v1/events/batch" {
			sawEvents = true
		}
	}
	srv.mu.Unlock()
	if !sawEvents {
		t.Fatal("test setup: no telemetry was flushed")
	}
	all := srv.everything()
	for _, leaked := range []string{"CANARY", "123-45-6789", "alice@", "patient_records", "/upload"} {
		if strings.Contains(all, leaked) {
			t.Errorf("%q reached the server", leaked)
		}
	}
}
