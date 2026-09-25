package converter

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type chatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  json.RawMessage `json:"tool_calls"`
	ToolCallID string          `json:"tool_call_id"`
	Name       string          `json:"name"`
}

// ConvertChatRequest converts an OpenAI Chat Completions request to Grok Responses format.
func ConvertChatRequest(body []byte, model string) ([]byte, error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(body, &source); err != nil {
		return nil, fmt.Errorf("parse chat request: %w", err)
	}

	var messages []chatMessage
	if err := json.Unmarshal(source["messages"], &messages); err != nil || len(messages) == 0 {
		return nil, errors.New("messages must be a non-empty array")
	}

	input, err := convertMessages(messages)
	if err != nil {
		return nil, err
	}

	target := map[string]json.RawMessage{
		"model": mustJSON(model),
		"input": mustJSON(input),
	}

	copyFields(target, source, "stream", "temperature", "top_p", "parallel_tool_calls", "metadata", "store", "service_tier")

	if raw := source["user"]; !isEmptyJSON(raw) {
		var user string
		if json.Unmarshal(raw, &user) == nil && strings.TrimSpace(user) != "" {
			target["safety_identifier"] = mustJSON(strings.TrimSpace(user))
		}
	}

	if raw := firstJSON(source["max_completion_tokens"], source["max_tokens"]); !isEmptyJSON(raw) {
		target["max_output_tokens"] = raw
	}

	if raw := source["reasoning_effort"]; !isEmptyJSON(raw) {
		target["reasoning"] = mustJSON(map[string]json.RawMessage{"effort": raw})
	}

	if raw := source["response_format"]; !isEmptyJSON(raw) {
		target["text"] = mustJSON(map[string]json.RawMessage{"format": raw})
	}

	var rawTools []any
	if raw := source["tools"]; !isEmptyJSON(raw) {
		if err := json.Unmarshal(raw, &rawTools); err != nil {
			return nil, fmt.Errorf("parse tools: %w", err)
		}
	}
	if !isEmptyJSON(source["web_search_options"]) {
		hasWebSearch := false
		for _, t := range rawTools {
			if m, ok := t.(map[string]any); ok && m["type"] == "web_search" {
				hasWebSearch = true
				break
			}
		}
		if !hasWebSearch {
			rawTools = append(rawTools, map[string]any{"type": "web_search"})
		}
	}
	// Flatten OpenAI nested function format to Responses flat format
	var tools []any
	for _, t := range rawTools {
		if flat := flattenTool(t); flat != nil {
			tools = append(tools, flat)
		}
	}
	if len(tools) > 0 {
		target["tools"] = mustJSON(tools)
	}

	if raw := source["tool_choice"]; !isEmptyJSON(raw) {
		target["tool_choice"] = flattenToolChoice(raw)
	}

	if raw := source["stop"]; !isEmptyJSON(raw) {
		var stop any
		if json.Unmarshal(raw, &stop) != nil {
			return nil, errors.New("invalid stop")
		}
		target["stop"] = mustJSON(stop)
	}

	return json.Marshal(target)
}

func convertMessages(messages []chatMessage) ([]any, error) {
	var out []any
	for _, msg := range messages {
		switch msg.Role {
		case "system":
			content := extractText(msg.Content)
			if content != "" {
				out = append(out, map[string]any{
					"type": "system", "content": content,
				})
			}
		case "user":
			content, err := convertContent(msg.Content)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{
				"role": "user", "content": content,
			})
		case "assistant":
			content := extractText(msg.Content)
			item := map[string]any{"role": "assistant"}
			if content != "" {
				item["content"] = content
			}
			if !isEmptyJSON(msg.ToolCalls) {
				var calls []map[string]any
				if json.Unmarshal(msg.ToolCalls, &calls) == nil {
					for _, c := range calls {
						fn, _ := c["function"].(map[string]any)
						if fn != nil {
							out = append(out, map[string]any{
								"type": "function_call",
								"call_id": c["id"],
								"name":  fn["name"],
								"arguments": fn["arguments"],
							})
						}
					}
				}
			}
			if len(item) > 1 {
				out = append(out, item)
			}
		case "tool":
			content := extractText(msg.Content)
			out = append(out, map[string]any{
				"type": "function_call_output",
				"call_id": msg.ToolCallID,
				"output": content,
			})
		}
	}
	return out, nil
}

func convertContent(raw json.RawMessage) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, nil
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) == nil {
		var out []map[string]any
		for _, p := range parts {
			var pType string
			json.Unmarshal(p["type"], &pType)
			if pType == "text" {
				var text string
				json.Unmarshal(p["text"], &text)
				out = append(out, map[string]any{"type": "input_text", "text": text})
			} else if pType == "image_url" {
				var img struct {
					URL string `json:"url"`
				}
				json.Unmarshal(p["image_url"], &img)
				out = append(out, map[string]any{"type": "input_image", "image_url": img.URL})
			}
		}
		return out, nil
	}
	return string(raw), nil
}

func extractText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []map[string]json.RawMessage
	if json.Unmarshal(raw, &parts) == nil {
		var sb strings.Builder
		for _, p := range parts {
			var pType string
			json.Unmarshal(p["type"], &pType)
			if pType == "text" {
				var text string
				json.Unmarshal(p["text"], &text)
				sb.WriteString(text)
			}
		}
		return sb.String()
	}
	return string(raw)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

func firstJSON(values ...json.RawMessage) json.RawMessage {
	for _, v := range values {
		if !isEmptyJSON(v) {
			return v
		}
	}
	return nil
}

func copyFields(target, source map[string]json.RawMessage, fields ...string) {
	for _, f := range fields {
		if v, ok := source[f]; ok && !isEmptyJSON(v) {
			target[f] = v
		}
	}
}

// flattenTool converts OpenAI nested tool format {type, function:{name,description,parameters}}
// to Responses flat format {type, name, description, parameters}. Non-function tools pass through.
func flattenTool(t any) any {
	m, ok := t.(map[string]any)
	if !ok {
		return t
	}
	fn, ok := m["function"].(map[string]any)
	if !ok {
		return t // already flat or non-function type (web_search etc)
	}
	flat := map[string]any{"type": "function"}
	if name, ok := fn["name"].(string); ok {
		flat["name"] = name
	}
	if desc, ok := fn["description"].(string); ok {
		flat["description"] = desc
	}
	if params, ok := fn["parameters"]; ok {
		flat["parameters"] = params
	}
	return flat
}

// flattenToolChoice converts OpenAI {type:function, function:{name}} to Responses {type:function, name}.
// String choices ("auto", "none", "required") pass through unchanged.
func flattenToolChoice(raw json.RawMessage) json.RawMessage {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return raw
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return raw
	}
	fn, ok := m["function"].(map[string]any)
	if !ok {
		return raw
	}
	flat := map[string]any{"type": "function"}
	if name, ok := fn["name"].(string); ok {
		flat["name"] = name
	}
	return mustJSON(flat)
}
