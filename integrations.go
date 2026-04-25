package thoth

// instrumentToolMap wraps a map of tool functions with governance while
// preserving tool names as map keys.
func (c *Client) instrumentToolMap(toolFns map[string]ToolFunc) map[string]ToolFunc {
	wrapped := make(map[string]ToolFunc, len(toolFns))
	for name, fn := range toolFns {
		wrapped[name] = c.WrapToolFunc(name, fn)
	}
	return wrapped
}

// InstrumentAnthropic wraps Anthropic-style tool function maps with Thoth governance.
//
// The returned map has the same keys as toolFns but governed callables.
func (c *Client) InstrumentAnthropic(toolFns map[string]ToolFunc) map[string]ToolFunc {
	return c.instrumentToolMap(toolFns)
}

// InstrumentOpenAI wraps OpenAI-style tool function maps with Thoth governance.
//
// The returned map has the same keys as toolFns but governed callables.
func (c *Client) InstrumentOpenAI(toolFns map[string]ToolFunc) map[string]ToolFunc {
	return c.instrumentToolMap(toolFns)
}

// WrapAnthropicTools is a legacy alias for InstrumentAnthropic.
func (c *Client) WrapAnthropicTools(toolFns map[string]ToolFunc) map[string]ToolFunc {
	return c.InstrumentAnthropic(toolFns)
}

// WrapOpenAITools is a legacy alias for InstrumentOpenAI.
func (c *Client) WrapOpenAITools(toolFns map[string]ToolFunc) map[string]ToolFunc {
	return c.InstrumentOpenAI(toolFns)
}
