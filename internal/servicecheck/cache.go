package servicecheck

import (
	"sync"
	"time"
)

type Cache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	results   []Result
	expiresAt time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, entries: make(map[string]cacheEntry)}
}

func (c *Cache) Get(ip string) ([]Result, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[ip]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return append([]Result(nil), entry.results...), true
}

func (c *Cache) Set(ip string, results []Result) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = cacheEntry{results: append([]Result(nil), results...), expiresAt: time.Now().Add(c.ttl)}
	if len(c.entries) > 5000 {
		for key, entry := range c.entries {
			if time.Now().After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
	}
}

func (c *Cache) StaleIPs(ips []string) []string {
	if c == nil {
		return ips
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	stale := make([]string, 0, len(ips))
	for _, ip := range ips {
		entry, ok := c.entries[ip]
		if !ok || time.Now().After(entry.expiresAt) {
			stale = append(stale, ip)
		}
	}
	return stale
}
