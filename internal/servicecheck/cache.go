package servicecheck

import (
	"sort"
	"sync"
	"time"
)

type RouteKey struct {
	Route string
	IP    string
}

type CacheState string

const (
	CacheFresh   CacheState = "fresh"
	CacheStale   CacheState = "stale"
	CacheMissing CacheState = "missing"
)

type CachedResult struct {
	Result Result
	State  CacheState
}

type Coverage struct {
	Eligible int
	Fresh    int
	Stale    int
	Missing  int
}

type Cache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[RouteKey]map[string]cacheEntry
}

type cacheEntry struct {
	result    Result
	checkedAt time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, entries: make(map[RouteKey]map[string]cacheEntry)}
}

func (c *Cache) Set(key RouteKey, result Result) {
	c.SetAt(key, result, time.Now())
}

func (c *Cache) SetAt(key RouteKey, result Result, checkedAt time.Time) {
	if c == nil || c.ttl <= 0 || key.Route == "" || key.IP == "" || result.Service == "" {
		return
	}
	c.mu.Lock()
	if c.entries[key] == nil {
		c.entries[key] = make(map[string]cacheEntry)
	}
	c.entries[key][result.Service] = cacheEntry{result: result, checkedAt: checkedAt}
	c.mu.Unlock()
}

func (c *Cache) Results(key RouteKey) []CachedResult {
	return c.ResultsAt(key, time.Now())
}

func (c *Cache) ResultsAt(key RouteKey, now time.Time) []CachedResult {
	if c == nil || c.ttl <= 0 {
		return nil
	}
	c.mu.RLock()
	byService := c.entries[key]
	results := make([]CachedResult, 0, len(byService))
	for _, entry := range byService {
		state := CacheFresh
		if now.Sub(entry.checkedAt) >= c.ttl {
			state = CacheStale
		}
		results = append(results, CachedResult{Result: entry.result, State: state})
	}
	c.mu.RUnlock()
	sort.Slice(results, func(i, j int) bool { return results[i].Result.Service < results[j].Result.Service })
	return results
}

func (c *Cache) StaleServices(key RouteKey, services []string) []string {
	return c.StaleServicesAt(key, services, time.Now())
}

func (c *Cache) StaleServicesAt(key RouteKey, services []string, now time.Time) []string {
	if c == nil {
		return append([]string(nil), services...)
	}
	type candidate struct {
		service   string
		missing   bool
		checkedAt time.Time
	}
	c.mu.RLock()
	byService := c.entries[key]
	candidates := make([]candidate, 0, len(services))
	for _, service := range services {
		entry, ok := byService[service]
		if !ok {
			candidates = append(candidates, candidate{service: service, missing: true})
			continue
		}
		if now.Sub(entry.checkedAt) >= c.ttl {
			candidates = append(candidates, candidate{service: service, checkedAt: entry.checkedAt})
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
		return candidates[i].service < candidates[j].service
	})
	result := make([]string, len(candidates))
	for i, candidate := range candidates {
		result[i] = candidate.service
	}
	return result
}

func (c *Cache) Coverage(keys []RouteKey, services []string) Coverage {
	return c.CoverageAt(keys, services, time.Now())
}

func (c *Cache) CoverageAt(keys []RouteKey, services []string, now time.Time) Coverage {
	coverage := Coverage{}
	seen := make(map[RouteKey]struct{}, len(keys))
	for _, key := range keys {
		if key.Route == "" || key.IP == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		coverage.Eligible++
		results := c.ResultsAt(key, now)
		if len(results) == 0 {
			coverage.Missing++
			continue
		}
		fresh := make(map[string]bool, len(results))
		for _, result := range results {
			fresh[result.Result.Service] = result.State == CacheFresh
		}
		allFresh := true
		for _, service := range services {
			if !fresh[service] {
				allFresh = false
				break
			}
		}
		if allFresh {
			coverage.Fresh++
		} else {
			coverage.Stale++
		}
	}
	return coverage
}
