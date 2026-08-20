package ipintel

import (
	"sync"
	"time"
)

// cache stores Intel by public IP for a bounded TTL.
type cache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	intel     Intel
	expiresAt time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, entries: make(map[string]cacheEntry)}
}

func (c *cache) get(ip string) (Intel, bool) {
	if c == nil || c.ttl <= 0 {
		return Intel{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[ip]
	if !ok || time.Now().After(entry.expiresAt) {
		return Intel{}, false
	}
	return entry.intel, true
}

func (c *cache) set(ip string, intel Intel) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = cacheEntry{intel: intel, expiresAt: time.Now().Add(c.ttl)}
	if len(c.entries) > 5000 {
		for key, entry := range c.entries {
			if time.Now().After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
	}
}
