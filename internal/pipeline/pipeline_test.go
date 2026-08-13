package pipeline

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/quality"
	"github.com/michael/vless-sub-server/internal/rename"
)

func TestCanPublishRejectsEmptyReplacementOfExistingCache(t *testing.T) {
	if CanPublish(0, true) {
		t.Fatal("empty refresh must not replace a populated cache")
	}
	if !CanPublish(1, true) {
		t.Fatal("non-empty refresh must be publishable")
	}
	if CanPublish(0, false) {
		t.Fatal("empty initial refresh must remain unavailable")
	}
}

func TestUpdateRuntimeRetainsFreshBandwidthMeasurement(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore(), cfg: &config.Config{BandwidthRefreshAfter: time.Hour}}
	key := "one"
	p.runtime.Set(quality.Runtime{Key: key, HasScore: true, ScoreEWMA: 30, LastBandwidthSuccessAt: time.Now(), Metrics: quality.Metrics{DownloadMbps: 50, BandwidthMeasured: true, BandwidthFresh: true}})
	p.updateRuntime(key, &exitprobe.ExitProbeResult{Metrics: quality.Metrics{InternetReachable: true, SampleCount: 5, SuccessCount: 5, RequestLatencyMS: 100}}, time.Now())
	runtime, _ := p.runtime.Get(key)
	if runtime.Metrics.DownloadMbps != 50 || !runtime.Metrics.BandwidthFresh {
		t.Fatalf("bandwidth was lost: %#v", runtime.Metrics)
	}
}

func TestUpdateRuntimeStabilizesDirectAndWarpCountries(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore(), cfg: &config.Config{BandwidthRefreshAfter: time.Hour}}
	key := "country"
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	metrics := quality.Metrics{InternetReachable: true, SampleCount: 5, SuccessCount: 5, RequestLatencyMS: 100}
	p.updateRuntime(key, &exitprobe.ExitProbeResult{
		Metrics:       metrics,
		DirectCountry: country.Observation{IP: netip.MustParseAddr("203.0.113.1"), Country: "AE"},
		WarpCountry:   country.Observation{IP: netip.MustParseAddr("198.51.100.1"), Country: "FI"},
	}, now)
	runtime, _ := p.runtime.Get(key)
	if runtime.Countries.DirectV4.Country != "AE" || runtime.Countries.WarpV4.Country != "FI" {
		t.Fatalf("countries = %#v", runtime.Countries)
	}

	// Missing observations retain the established route countries.
	p.updateRuntime(key, &exitprobe.ExitProbeResult{Metrics: metrics}, now.Add(time.Minute))
	runtime, _ = p.runtime.Get(key)
	if runtime.Countries.DirectV4.Country != "AE" || runtime.Countries.WarpV4.Country != "FI" {
		t.Fatalf("countries were erased: %#v", runtime.Countries)
	}
}

func TestStateRankOrdersRecoveringBeforeDegraded(t *testing.T) {
	if !(StateRank("HEALTHY") < StateRank("RECOVERING") && StateRank("RECOVERING") < StateRank("DEGRADED")) {
		t.Fatal("unexpected state ordering")
	}
}

func TestOutputEntriesExcludeDeadAndOrderByStateThenScore(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore()}
	records := []parse.ProxyRecord{
		{Protocol: parse.VLESS, Host: "healthy.example", Port: 443, UUIDOrPassword: "one"},
		{Protocol: parse.VLESS, Host: "recovering.example", Port: 443, UUIDOrPassword: "two"},
		{Protocol: parse.VLESS, Host: "degraded.example", Port: 443, UUIDOrPassword: "three"},
		{Protocol: parse.VLESS, Host: "dead.example", Port: 443, UUIDOrPassword: "four"},
	}
	for _, record := range records {
		state, score := quality.Healthy, 20.0
		switch record.Host {
		case "recovering.example":
			state, score = quality.Recovering, 1
		case "degraded.example":
			state, score = quality.Degraded, 1
		case "dead.example":
			state, score = quality.Dead, 0
		}
		p.runtime.Set(quality.Runtime{Key: identity(record), State: state, ScoreEWMA: score})
	}
	result := RefreshResult{}
	entries, _ := p.outputEntries(records, nil, map[string]*dns.DNSResult{
		"healthy.example": {}, "recovering.example": {}, "degraded.example": {}, "dead.example": {},
	}, &result)
	if len(entries) != 3 || entries[0].Record.Host != "healthy.example" || entries[1].Record.Host != "recovering.example" || entries[2].Record.Host != "degraded.example" {
		t.Fatalf("entries = %#v", entries)
	}
	if result.Dead != 1 {
		t.Fatalf("dead = %d, want 1", result.Dead)
	}
}

func TestOutputEntriesUsesEndpointGeoWhenDirectExitIsUnavailable(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore()}
	record := parse.ProxyRecord{Protocol: parse.VLESS, Host: "balancer.example", Port: 443, UUIDOrPassword: "one"}
	p.runtime.Set(quality.Runtime{Key: identity(record), State: quality.Degraded})

	entries, _ := p.outputEntries([]parse.ProxyRecord{record}, nil, map[string]*dns.DNSResult{
		"balancer.example": {IP: "198.51.100.1", EndpointGeo: &geo.GeoInfo{CountryCode: "PL", City: "Warsaw", ISP: "Example Networks", IP: "198.51.100.1"}},
	}, &RefreshResult{})
	if len(entries) != 1 || entries[0].Geo == nil || entries[0].Geo.City != "Warsaw" {
		t.Fatalf("endpoint geo was not used: %#v", entries)
	}
}

func TestCachedReturnsDeepCopiedTypedSnapshot(t *testing.T) {
	p := &Pipeline{}
	p.cache.Store(&CachedData{
		Entries: []CachedEntry{{
			Entry: rename.RenamedEntry{
				Record:          parse.ProxyRecord{Host: "one.example", QueryParams: map[string]string{"type": "xhttp", "path": "/one"}},
				RenamedFragment: "One",
			},
			Countries: country.RouteCountries{WarpV4: country.FamilyResult{Available: true, Country: "FI", Status: country.Confirmed}},
		}},
		JSONOutput: []byte("[]"),
	})

	first, ok := p.Cached()
	if !ok {
		t.Fatal("cache unavailable")
	}
	first.Entries[0].Entry.Record.QueryParams["path"] = "/changed"
	first.Entries[0].Entry.RenamedFragment = "Changed"
	first.JSONOutput[0] = '{'

	second, _ := p.Cached()
	if second.Entries[0].Entry.Record.QueryParams["path"] != "/one" || second.Entries[0].Entry.RenamedFragment != "One" || string(second.JSONOutput) != "[]" {
		t.Fatalf("cache was mutated through copy: %#v", second)
	}
}

func TestSelectWarpReprobeCandidatesSkipsConfirmedWarpRoutes(t *testing.T) {
	entries := []CachedEntry{
		{Entry: rename.RenamedEntry{Record: parse.ProxyRecord{Host: "confirmed"}}, WarpHealthy: true, Countries: country.RouteCountries{WarpV4: country.FamilyResult{Available: true, Country: "FI", Status: country.Confirmed}}},
		{Entry: rename.RenamedEntry{Record: parse.ProxyRecord{Host: "missing"}}, WarpHealthy: true},
		{Entry: rename.RenamedEntry{Record: parse.ProxyRecord{Host: "not-warp"}}, WarpHealthy: false},
	}
	got := selectWarpReprobeCandidates(entries)
	if len(got) != 1 || got[0].Host != "missing" {
		t.Fatalf("candidates = %#v", got)
	}
}

func TestRebuildCachedCountriesIncludesWarpVerifiedDirectEntries(t *testing.T) {
	record := parse.ProxyRecord{Protocol: parse.VLESS, Host: "warp-verified.example", Port: 443, UUIDOrPassword: "one", QueryParams: map[string]string{"type": "tcp"}}
	p := &Pipeline{runtime: quality.NewStore()}
	p.runtime.Set(quality.Runtime{Key: identity(record), DirectHealthy: false, WarpHealthy: true})
	p.rebuildCachedCountries(&CachedData{
		Entries:  []CachedEntry{{Entry: rename.RenamedEntry{Record: record, RenamedFragment: "Warp Verified"}}},
		Metadata: format.FormatMetadata{TotalAlive: 1},
	})
	cached, ok := p.Cached()
	if !ok || !strings.Contains(cached.Output, "vless://") || !strings.Contains(cached.Output, "# Количество: 1") {
		t.Fatalf("direct output = %#v", cached)
	}
}
