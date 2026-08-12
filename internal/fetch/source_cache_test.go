package fetch

import (
	"testing"
	"time"
)

func TestSourceCacheReusesRetryableFailure(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	cache := NewSourceCache()
	cache.Merge(now, []FetchResult{{URL: "one", Status: "ok", Lines: []string{"vless://old"}}}, 6*time.Hour)
	lines := cache.Merge(now.Add(time.Minute), []FetchResult{{URL: "one", Status: "error", Error: "HTTP 503"}}, 6*time.Hour)
	if len(lines) != 1 || lines[0] != "vless://old" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestSourceCacheClearsAuthoritativeEmptyResponse(t *testing.T) {
	now := time.Now()
	cache := NewSourceCache()
	cache.Merge(now, []FetchResult{{URL: "one", Status: "ok", Lines: []string{"vless://old"}}}, time.Hour)
	lines := cache.Merge(now.Add(time.Minute), []FetchResult{{URL: "one", Status: "error", Error: "HTTP 404"}}, time.Hour)
	if len(lines) != 0 {
		t.Fatalf("lines = %#v, want empty", lines)
	}
}

func TestSourceCacheExpiresStaleResult(t *testing.T) {
	now := time.Now()
	cache := NewSourceCache()
	cache.Merge(now, []FetchResult{{URL: "one", Status: "ok", Lines: []string{"vless://old"}}}, time.Hour)
	lines := cache.Merge(now.Add(2*time.Hour), []FetchResult{{URL: "one", Status: "error", Error: "timeout"}}, time.Hour)
	if len(lines) != 0 {
		t.Fatalf("lines = %#v, want expired", lines)
	}
}
