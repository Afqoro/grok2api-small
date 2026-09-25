package converter

import (
	"sync"
	"time"
)

const (
	reasoningCacheCapacity = 2048
	reasoningCacheTTL      = 30 * time.Minute
)

// ReasoningItem holds a reasoning proof (item id + encrypted content) returned
// by the upstream Responses API.
type ReasoningItem struct {
	ID        string
	Encrypted string
}

type reasoningEntry struct {
	item      ReasoningItem
	createdAt time.Time
}

// ReasoningCache stores short-lived reasoning proofs keyed by conversation
// scope + tool call ID, so multi-turn tool calls can replay the reasoning
// item upstream instead of losing chain-of-thought state between requests.
type ReasoningCache struct {
	mu      sync.Mutex
	entries map[string]reasoningEntry
}

func NewReasoningCache() *ReasoningCache {
	return &ReasoningCache{entries: make(map[string]reasoningEntry)}
}

// Set records one proof keyed by tool call ID (upstream call IDs are unique).
// No-ops on empty fields.
func (c *ReasoningCache) Set(callID string, item ReasoningItem) {
	if c == nil || callID == "" || item.ID == "" || item.Encrypted == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if len(c.entries) >= reasoningCacheCapacity {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			if now.Sub(e.createdAt) > reasoningCacheTTL {
				delete(c.entries, k)
				continue
			}
			if oldestKey == "" || e.createdAt.Before(oldest) {
				oldestKey, oldest = k, e.createdAt
			}
		}
		if len(c.entries) >= reasoningCacheCapacity && oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[callID] = reasoningEntry{item: item, createdAt: now}
}

// Get returns the proof for a callID, or false when absent/expired.
func (c *ReasoningCache) Get(callID string) (ReasoningItem, bool) {
	if c == nil || callID == "" {
		return ReasoningItem{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[callID]
	if !ok || time.Since(e.createdAt) > reasoningCacheTTL {
		return ReasoningItem{}, false
	}
	return e.item, true
}

// defaultReasoningCache is the process-wide cache used by the converter layer.
var defaultReasoningCache = NewReasoningCache()

// CaptureReasoningFromOutput extracts reasoning items (id + encrypted_content)
// from a Responses API output array and stores them keyed by call_id so the
// next turn can replay them upstream.
func CaptureReasoningFromOutput(output []map[string]any) {
	if len(output) == 0 {
		return
	}
	var pending ReasoningItem
	hasPending := false
	for _, item := range output {
		itemType, _ := item["type"].(string)
		switch itemType {
		case "reasoning":
			id, _ := item["id"].(string)
			enc, _ := item["encrypted_content"].(string)
			if id != "" && enc != "" {
				pending = ReasoningItem{ID: id, Encrypted: enc}
				hasPending = true
			}
		case "function_call":
			if hasPending {
				if callID, _ := item["call_id"].(string); callID != "" {
					defaultReasoningCache.Set(callID, pending)
				}
				hasPending = false
			}
		}
	}
}

// DefaultReasoningCacheForTest exposes the default cache for verification tests.
func DefaultReasoningCacheForTest() *ReasoningCache { return defaultReasoningCache }
