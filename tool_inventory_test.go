package thoth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegisterToolInventoryHasNoClassAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant/thoth/tool-inventory" || r.Header.Get("x-api-key") != "runtime" {
			t.Error("incorrect scoped inventory request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["source"] != "go_sdk" {
			t.Error("incorrect source")
		}
		tools := body["tools"].([]any)
		tool := tools[0].(map[string]any)
		if _, exists := tool["classes"]; exists {
			t.Error("SDK sent authority")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	c := &Client{cfg: Config{TenantID: "tenant", AgentID: "agent", APIURL: server.URL, APIKey: "runtime"}, http: server.Client()}
	if err := c.RegisterToolInventory(context.Background(), []ToolMetadata{{Name: "orders.list", Description: "List orders", InputSchema: map[string]any{"type": "object"}}}); err != nil {
		t.Fatal(err)
	}
}

func TestInventorySanitizesSchemaWithoutMutatingCaller(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"token": map[string]any{"type": "string", "default": "secret", "enum": []any{"secret"}}}}
	clean := stripInventoryValues(schema, false).(map[string]any)
	property := clean["properties"].(map[string]any)["token"].(map[string]any)
	if len(property) != 1 || property["type"] != "string" {
		t.Fatal("value metadata retained")
	}
	if len(schema["properties"].(map[string]any)["token"].(map[string]any)) != 3 {
		t.Fatal("caller schema mutated")
	}
}

func TestInstrumentDoesNotWaitForInventory(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "tool-inventory") {
			close(entered)
			<-release
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	c, err := NewClient(Config{TenantID: "t", AgentID: "a", APIURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	finished := make(chan struct{})
	go func() {
		c.instrumentToolMap(map[string]ToolFunc{"read": func(context.Context, map[string]any) (any, error) { return nil, nil }})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("instrument blocked on inventory")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("inventory did not start")
	}
	close(release)
}

func TestInventoryRetainsParameterNamedDefault(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"default": map[string]any{"type": "string", "default": "secret"}}}
	clean := stripInventoryValues(schema, false).(map[string]any)["properties"].(map[string]any)["default"].(map[string]any)
	if len(clean) != 1 || clean["type"] != "string" {
		t.Fatal("default parameter lost or value retained")
	}
}
