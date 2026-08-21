package servicecheck

import (
	"reflect"
	"testing"
	"time"
)

func TestCacheSeparatesRoutesAndExpiresPerService(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	cache := NewCache(time.Hour)
	cache.SetAt(RouteKey{Route: "direct", IP: "203.0.113.1"}, Result{Service: "gemini", Status: Available}, now.Add(-2*time.Hour))
	cache.SetAt(RouteKey{Route: "direct", IP: "203.0.113.1"}, Result{Service: "netflix", Status: Blocked}, now.Add(-time.Minute))
	cache.SetAt(RouteKey{Route: "warp", IP: "203.0.113.1"}, Result{Service: "gemini", Status: Blocked}, now.Add(-time.Minute))

	direct := cache.ResultsAt(RouteKey{Route: "direct", IP: "203.0.113.1"}, now)
	if len(direct) != 2 || direct[0].Result.Service != "gemini" || direct[0].State != CacheStale || direct[1].Result.Service != "netflix" || direct[1].State != CacheFresh {
		t.Fatalf("direct results = %#v", direct)
	}
	warp := cache.ResultsAt(RouteKey{Route: "warp", IP: "203.0.113.1"}, now)
	if len(warp) != 1 || warp[0].Result.Status != Blocked || warp[0].State != CacheFresh {
		t.Fatalf("warp results = %#v", warp)
	}

	stale := cache.StaleServicesAt(RouteKey{Route: "direct", IP: "203.0.113.1"}, []string{"gemini", "netflix", "reddit"}, now)
	if !reflect.DeepEqual(stale, []string{"reddit", "gemini"}) {
		t.Fatalf("stale services = %#v", stale)
	}
}

func TestCacheCoverageUsesWholeRouteTarget(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	cache := NewCache(time.Hour)
	fresh := RouteKey{Route: "direct", IP: "203.0.113.1"}
	partial := RouteKey{Route: "direct", IP: "203.0.113.2"}
	missing := RouteKey{Route: "direct", IP: "203.0.113.3"}
	for _, service := range []string{"gemini", "netflix"} {
		cache.SetAt(fresh, Result{Service: service, Status: Available}, now)
	}
	cache.SetAt(partial, Result{Service: "gemini", Status: Available}, now)

	coverage := cache.CoverageAt([]RouteKey{fresh, partial, missing}, []string{"gemini", "netflix"}, now)
	if coverage.Eligible != 3 || coverage.Fresh != 1 || coverage.Stale != 1 || coverage.Missing != 1 {
		t.Fatalf("coverage = %#v", coverage)
	}
}
