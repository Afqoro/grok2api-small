package converter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"net/http"
)

type StreamConverter struct {
	writer  *bufio.Writer
	flusher http.Flusher
	id      string
	model   string
	created int64
	started bool
	finished bool

	tools map[string]streamTool
	stopSequence string
	lastUsage map[string]any
}

type streamTool struct {
	Index   int
	ID      string
	Name    string
	Arguments string
	SentArgs  bool
	Closed   bool
}

func NewStreamConverter(w io.Writer, model string) *StreamConverter {
	bw, ok := w.(*bufio.Writer)
	if !ok {
		bw = bufio.NewWriter(w)
	}
	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	return &StreamConverter{
		writer:  bw,
		flusher: flusher,
		id:      "chatcmpl-" + randHex(24),
		model:   model,
		created: time.Now().Unix(),
		tools:   make(map[string]streamTool),
	}
}

func (c *StreamConverter) writeSSE(data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.writer, "data: %s\n\n", b); err != nil {
		return err
	}
	c.writer.Flush()
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return nil
}

func (c *StreamConverter) start() error {
	if c.started {
		return nil
	}
	c.started = true
	return c.writeSSE(map[string]any{
		"id":      c.id,
		"object":  "chat.completion.chunk",
		"created": c.created,
		"model":   c.model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
	})
}

func (c *StreamConverter) textDelta(delta string) error {
	if err := c.start(); err != nil {
		return err
	}
	return c.writeSSE(map[string]any{
		"id": c.id, "object": "chat.completion.chunk", "created": c.created, "model": c.model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": delta}, "finish_reason": nil}},
	})
}

func (c *StreamConverter) toolStart(itemKey, callID, name, arguments string) error {
	if err := c.start(); err != nil {
		return err
	}
	if _, exists := c.tools[itemKey]; exists {
		return nil
	}
	tool := streamTool{Index: len(c.tools), ID: callID, Name: name, Arguments: arguments}
	c.tools[itemKey] = tool
	return c.writeSSE(map[string]any{
		"id": c.id, "object": "chat.completion.chunk", "created": c.created, "model": c.model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{
			"index": tool.Index, "id": tool.ID, "type": "function", "function": map[string]any{"name": tool.Name, "arguments": ""},
		}}}, "finish_reason": nil}},
	})
}

func (c *StreamConverter) toolDelta(id, delta string) error {
	tool, ok := c.tools[id]
	if !ok {
		return nil
	}
	tool.SentArgs = true
	c.tools[id] = tool
	return c.writeSSE(map[string]any{
		"id": c.id, "object": "chat.completion.chunk", "created": c.created, "model": c.model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{
			"index": tool.Index, "function": map[string]any{"arguments": delta},
		}}}, "finish_reason": nil}},
	})
}

func (c *StreamConverter) done(status string, usage map[string]any) error {
	c.lastUsage = usage
	finishReason := "stop"
	if len(c.tools) > 0 {
		finishReason = "tool_calls"
	} else if status == "incomplete" {
		finishReason = "length"
	}
	if err := c.writeSSE(map[string]any{
		"id": c.id, "object": "chat.completion.chunk", "created": c.created, "model": c.model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": finishReason}},
		"usage": usage,
	}); err != nil {
		return err
	}
	c.finished = true
	_, err := fmt.Fprintf(c.writer, "data: [DONE]\n\n")
	c.writer.Flush()
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return err
}

func (c *StreamConverter) streamError(msg string) error {
	if err := c.writeSSE(map[string]any{"error": map[string]any{"message": msg, "type": "api_error"}}); err != nil {
		return err
	}
	_, err := fmt.Fprintf(c.writer, "data: [DONE]\n\n")
	c.writer.Flush()
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return err
}

// ProcessStream reads SSE from upstream Responses API and converts to OpenAI chat completion chunks.
func (c *StreamConverter) ProcessStream(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)

	var status string
	var usage map[string]any

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var event map[string]any
		if json.Unmarshal([]byte(data), &event) == nil {
			c.handleEvent(event, &status, &usage)
		}
	}

	if !c.finished {
		c.done(status, usage)
	}
	return scanner.Err()
}

func (c *StreamConverter) handleEvent(event map[string]any, status *string, usage *map[string]any) {
	if t, ok := event["type"].(string); ok {
		switch t {
		case "response.output_text.delta":
			if delta, ok := event["delta"].(string); ok {
				c.textDelta(delta)
			}
		case "response.output_item.added":
			item, _ := event["item"].(map[string]any)
			if item != nil {
				itemType, _ := item["type"].(string)
				if itemType == "function_call" {
					itemID, _ := item["id"].(string)
					callID, _ := item["call_id"].(string)
					name, _ := item["name"].(string)
					args, _ := item["arguments"].(string)
					c.toolStart(itemID, callID, name, args)
				}
			}
		case "response.function_call_arguments.delta":
			itemID, _ := event["item_id"].(string)
			delta, _ := event["delta"].(string)
			c.toolDelta(itemID, delta)
		case "response.completed":
			if resp, ok := event["response"].(map[string]any); ok {
				if s, ok := resp["status"].(string); ok {
					*status = s
				}
				if u, ok := resp["usage"].(map[string]any); ok {
					*usage = convertUsage(u)
				}
				if out, ok := resp["output"].([]any); ok {
					var items []map[string]any
					for _, raw := range out {
						if m, ok := raw.(map[string]any); ok {
							items = append(items, m)
						}
					}
					CaptureReasoningFromOutput(items)
				}
			}
			c.done(*status, *usage)
		case "error":
			msg := "upstream error"
			if e, ok := event["error"].(map[string]any); ok {
				if m, ok := e["message"].(string); ok {
					msg = m
				}
			}
			c.streamError(msg)
		}
	}
}

func convertUsage(u map[string]any) map[string]any {
	result := map[string]any{
		"prompt_tokens":     0,
		"completion_tokens": 0,
		"total_tokens":      0,
	}
	if v, ok := u["input_tokens"]; ok {
		result["prompt_tokens"] = v
	}
	if v, ok := u["output_tokens"]; ok {
		result["completion_tokens"] = v
	}
	prompt := toInt(result["prompt_tokens"])
	completion := toInt(result["completion_tokens"])
	result["total_tokens"] = prompt + completion
	return result
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

func randHex(n int) string {
	b := make([]byte, n/2)
	for i := range b {
		b[i] = byte('a' + (i % 26))
	}
	return string(b)
}

// LastUsage returns the token usage captured from the most recent stream.
func (c *StreamConverter) LastUsage() map[string]any { return c.lastUsage }
