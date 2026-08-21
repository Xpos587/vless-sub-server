package enrichment

import (
	"sort"
	"sync"
	"time"
)

type State string

const (
	Fresh   State = "fresh"
	Stale   State = "stale"
	Missing State = "missing"
)

type Coverage struct {
	Eligible int
	Fresh    int
	Stale    int
	Missing  int
}

type Cache[T any] struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]entry[T]
}

type entry[T any] struct {
	value     T
	checkedAt time.Time
}

func NewCache[T any](ttl time.Duration) *Cache[T] {
	return &Cache[T]{ttl: ttl, entries: make(map[string]entry[T])}
}

func (c *Cache[T]) Set(key string, value T) {
	c.SetAt(key, value, time.Now())
}

func (c *Cache[T]) SetAt(key string, value T, checkedAt time.Time) {
	if c == nil || c.ttl <= 0 || key == "" {
		return
	}
	c.mu.Lock()
	c.entries[key] = entry[T]{value: value, checkedAt: checkedAt}
	c.mu.Unlock()
}

func (c *Cache[T]) Get(key string) (T, State) {
	return c.GetAt(key, time.Now())
}

func (c *Cache[T]) GetAt(key string, now time.Time) (T, State) {
	var zero T
	if c == nil || c.ttl <= 0 || key == "" {
		return zero, Missing
	}
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return zero, Missing
	}
	if now.Sub(entry.checkedAt) >= c.ttl {
		return entry.value, Stale
	}
	return entry.value, Fresh
}

func (c *Cache[T]) StaleKeys(keys []string) []string {
	return c.StaleKeysAt(keys, time.Now())
}

func (c *Cache[T]) StaleKeysAt(keys []string, now time.Time) []string {
	if c == nil {
		return uniqueSorted(keys)
	}
	type candidate struct {
		key       string
		missing   bool
		checkedAt time.Time
	}
	seen := make(map[string]struct{}, len(keys))
	candidates := make([]candidate, 0, len(keys))
	c.mu.RLock()
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		entry, ok := c.entries[key]
		if !ok {
			candidates = append(candidates, candidate{key: key, missing: true})
			continue
		}
		if now.Sub(entry.checkedAt) >= c.ttl {
			candidates = append(candidates, candidate{key: key, checkedAt: entry.checkedAt})
		}
	}
	c.mu.RUnlock()
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].missing != candidates[j].missing {
			return candidates[i].missing
		}
		if !candidates[i].checkedAt.Equal(candidates[j].checkedAt) {
			return candidates[i].checkedAt.Before(candidates[j].checkedAt)
		}
		return candidates[i].key < candidates[j].key
	})
	result := make([]string, len(candidates))
	for i, candidate := range candidates {
		result[i] = candidate.key
	}
	return result
}

func (c *Cache[T]) Coverage(keys []string) Coverage {
	return c.CoverageAt(keys, time.Now())
}

func (c *Cache[T]) CoverageAt(keys []string, now time.Time) Coverage {
	coverage := Coverage{}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		coverage.Eligible++
		_, state := c.GetAt(key, now)
		switch state {
		case Fresh:
			coverage.Fresh++
		case Stale:
			coverage.Stale++
		default:
			coverage.Missing++
		}
	}
	return coverage
}

func uniqueSorted(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
