package thoth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ToolMetadata is advisory setup inventory, never a classification declaration.
type ToolMetadata struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// RegisterToolInventory sends metadata without granting execution authority.
func (c *Client) RegisterToolInventory(ctx context.Context, tools []ToolMetadata) error {
	if strings.EqualFold(os.Getenv("THOTH_TOOL_INVENTORY"), "off") {
		return nil
	}
	sanitized := make([]ToolMetadata, len(tools))
	for i, tool := range tools {
		sanitized[i] = tool
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return err
		}
		var schema any
		if err := json.Unmarshal(raw, &schema); err != nil {
			return err
		}
		sanitized[i].InputSchema, _ = stripInventoryValues(schema, false).(map[string]any)
	}
	tools = sanitized
	for offset := 0; offset < len(tools); offset += 100 {
		payload, err := json.Marshal(map[string]any{"agent_id": c.cfg.AgentID, "source": "go_sdk", "tools": tools[offset:min(offset+100, len(tools))]})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.APIURL, "/")+"/"+url.PathEscape(c.cfg.TenantID)+"/thoth/tool-inventory", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", c.cfg.APIKey)
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			return fmt.Errorf("tool inventory refused (%d)", resp.StatusCode)
		}
	}
	return nil
}

func stripInventoryValues(value any, namedMap bool) any {
	switch v := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range v {
			switch key {
			case "default", "examples", "example", "const", "enum":
				if !namedMap {
					continue
				}
			}
			result[key] = stripInventoryValues(item, !namedMap && (key == "properties" || key == "patternProperties" || key == "$defs" || key == "definitions"))
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = stripInventoryValues(item, false)
		}
		return result
	}
	return value
}
