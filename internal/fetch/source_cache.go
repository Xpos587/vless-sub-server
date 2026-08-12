package fetch

import (
	"strings"
	"sync"
	"time"
)

type sourceSnapshot struct {
	lines       []string
	lastSuccess time.Time
}

type SourceCache struct {
	mu        sync.Mutex
	snapshots map[string]sourceSnapshot
}

func NewSourceCache() *SourceCache {
	return &SourceCache{snapshots: make(map[string]sourceSnapshot)}
}

func (c *SourceCache) Merge(now time.Time, results []FetchResult, maxAge time.Duration) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var lines []string
	for _, result := range results {
		if result.Status == "ok" && len(result.Lines) > 0 {
			copyLines := append([]string(nil), result.Lines...)
			c.snapshots[result.URL] = sourceSnapshot{lines: copyLines, lastSuccess: now}
			lines = append(lines, copyLines...)
			continue
		}
		if isAuthoritativeFailure(result.Error) {
			delete(c.snapshots, result.URL)
			continue
		}
		if snapshot, ok := c.snapshots[result.URL]; ok && now.Sub(snapshot.lastSuccess) <= maxAge {
			lines = append(lines, snapshot.lines...)
		}
	}
	return lines
}

func isAuthoritativeFailure(err string) bool {
	return strings.HasPrefix(err, "HTTP 4") && !strings.HasPrefix(err, "HTTP 429")
}
