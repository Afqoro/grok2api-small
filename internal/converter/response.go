package converter

import (
	"encoding/json"
	"strings"
)

type responsesBody struct {
	ID        string `json:"id"`
	Object    string `json:"object"`
	Status    string `json:"status"`
	Model     string `json:"model"`
	Usage     map[string]any `json:"usage"`
	Output    []map[string]any `json:"output"`
}

// ConvertResponsesToChat converts a non-streaming Responses API body to OpenAI Chat Completions format.
func ConvertResponsesToChat(body []byte, model string) ([]byte, error) {
	var resp responsesBody
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	CaptureReasoningFromOutput(resp.Output)

	var content strings.Builder
	var toolCalls []map[string]any

	for _, item := range resp.Output {
		itemType, _ := item["type"].(string)
		switch itemType {
		case "message":
			if contentArr, ok := item["content"].([]any); ok {
				for _, c := range contentArr {
					if m, ok := c.(map[string]any); ok {
						if t, _ := m["type"].(string); t == "output_text" {
							if text, _ := m["text"].(string); text != "" {
								content.WriteString(text)
							}
						}
					}
				}
			}
		case "function_call":
			callID, _ := item["call_id"].(string)
			name, _ := item["name"].(string)
			args, _ := item["arguments"].(string)
			toolCalls = append(toolCalls, map[string]any{
				"id": callID,
				"type": "function",
				"function": map[string]any{
					"name": name,
					"arguments": args,
				},
			})
		}
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	} else if resp.Status == "incomplete" {
		finishReason = "length"
	}

	message := map[string]any{
		"role": "assistant",
	}
	if content.Len() > 0 {
		message["content"] = content.String()
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}

	result := map[string]any{
		"id":      strings.Replace(resp.ID, "resp_", "chatcmpl_", 1),
		"object":  "chat.completion",
		"created": 0,
		"model":   model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
		"usage": convertUsage(resp.Usage),
	}

	return json.Marshal(result)
}
