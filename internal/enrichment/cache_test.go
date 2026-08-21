package enrichment

import (
	"reflect"
	"testing"
	"time"
)

func TestCacheKeepsStaleValueAndOrdersMissingBeforeOldest(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	cache := NewCache[string](time.Hour)
	cache.SetAt("fresh", "fresh-value", now.Add(-30*time.Minute))
	cache.SetAt("old", "old-value", now.Add(-2*time.Hour))

	if value, state := cache.GetAt("old", now); value != "old-value" || state != Stale {
		t.Fatalf("old entry = %q, %q; want stale value", value, state)
	}
	if value, state := cache.GetAt("missing", now); value != "" || state != Missing {
		t.Fatalf("missing entry = %q, %q", value, state)
	}

	got := cache.StaleKeysAt([]string{"fresh", "old", "missing"}, now)
	want := []string{"missing", "old"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale keys = %#v, want %#v", got, want)
	}
}

func TestCacheCoverageCountsFreshStaleAndMissing(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	cache := NewCache[int](time.Hour)
	cache.SetAt("fresh", 1, now.Add(-time.Minute))
	cache.SetAt("stale", 2, now.Add(-2*time.Hour))

	coverage := cache.CoverageAt([]string{"fresh", "stale", "missing", "fresh"}, now)
	if coverage.Eligible != 3 || coverage.Fresh != 1 || coverage.Stale != 1 || coverage.Missing != 1 {
		t.Fatalf("coverage = %#v", coverage)
	}
}
