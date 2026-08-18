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

// MergedSource keeps per-source lines after applying the stale-cache policy,
// so metrics can attribute configs to the subscription that served them.
type MergedSource struct {
	URL      string
	Lines    []string
	FetchOK  bool
	Stale    bool
	ViaProxy bool
}

func (c *SourceCache) Merge(now time.Time, results []FetchResult, maxAge time.Duration) []string {
	detailed := c.MergeDetailed(now, results, maxAge)
	var lines []string
	for _, source := range detailed {
		lines = append(lines, source.Lines...)
	}
	return lines
}

func (c *SourceCache) MergeDetailed(now time.Time, results []FetchResult, maxAge time.Duration) []MergedSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	var merged []MergedSource
	for _, result := range results {
		if result.Status == "ok" {
			if len(result.Lines) == 0 {
				delete(c.snapshots, result.URL)
				merged = append(merged, MergedSource{URL: result.URL, FetchOK: true})
				continue
			}
			copyLines := append([]string(nil), result.Lines...)
			c.snapshots[result.URL] = sourceSnapshot{lines: copyLines, lastSuccess: now}
			merged = append(merged, MergedSource{URL: result.URL, Lines: copyLines, FetchOK: true, ViaProxy: result.Via != ""})
			continue
		}
		if isAuthoritativeFailure(result.Error) {
			delete(c.snapshots, result.URL)
			merged = append(merged, MergedSource{URL: result.URL})
			continue
		}
		if snapshot, ok := c.snapshots[result.URL]; ok && now.Sub(snapshot.lastSuccess) <= maxAge {
			merged = append(merged, MergedSource{URL: result.URL, Lines: append([]string(nil), snapshot.lines...), Stale: true})
			continue
		}
		merged = append(merged, MergedSource{URL: result.URL})
	}
	return merged
}

func isAuthoritativeFailure(err string) bool {
	return strings.HasPrefix(err, "HTTP 4") && !strings.HasPrefix(err, "HTTP 429")
}
