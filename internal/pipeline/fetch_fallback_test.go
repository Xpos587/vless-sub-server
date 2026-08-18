package pipeline

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

func fallbackEntry(host, countryCode string, direct, warp bool) CachedEntry {
	return CachedEntry{
		Entry: rename.RenamedEntry{
			Record: parse.ProxyRecord{
				Protocol: parse.VLESS, Host: host, Port: 443, UUIDOrPassword: "u",
				QueryParams: map[string]string{"type": "tcp"},
			},
			RenamedFragment: host,
		},
		Countries:     country.RouteCountries{DirectV4: country.FamilyResult{ObservedCountry: countryCode}},
		DirectHealthy: direct,
		WarpHealthy:   warp,
	}
}

func TestGatewayCandidatesPicksDistinctCountries(t *testing.T) {
	p := &Pipeline{}
	p.cache.Store(&CachedData{Entries: []CachedEntry{
		fallbackEntry("dead.example", "NL", false, true),
		fallbackEntry("nl-a.example", "NL", true, false),
		fallbackEntry("nl-b.example", "NL", true, true),
		fallbackEntry("de.example", "DE", true, true),
		fallbackEntry("fi.example", "FI", true, true),
		fallbackEntry("kz.example", "KZ", true, true),
	}})

	candidates := p.gatewayCandidates(6)
	if len(candidates) != 4 {
		t.Fatalf("candidates = %d, want 4 distinct countries", len(candidates))
	}
	countries := map[string]int{}
	for _, record := range candidates {
		if record.Host == "dead.example" {
			t.Fatal("direct-unhealthy record selected")
		}
		countries[record.Host]++
		if countries[record.Host] > 1 {
			t.Fatalf("duplicate candidate %s", record.Host)
		}
	}
	if candidates[0].Host != "nl-a.example" || candidates[1].Host == "nl-b.example" {
		t.Fatalf("country diversity broken: %v", candidates)
	}
}

func TestGatewayCandidatesEmptyWithoutCache(t *testing.T) {
	p := &Pipeline{}
	if got := p.gatewayCandidates(3); len(got) != 0 {
		t.Fatalf("candidates = %d without cache", len(got))
	}
}

func TestFetchAllSourcesFallsBackToDirectWhenProxyDead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://uuid@a.example.com:443?security=reality&sni=a.com#node\n"))
	}))
	defer server.Close()

	p := &Pipeline{cfg: &config.Config{
		SubscriptionURLs:   []string{server.URL},
		SourceFetchProxies: []string{"socks5://127.0.0.1:1"}, // closed port
	}}
	results := p.fetchAllSources(context.Background())
	if len(results) != 1 || results[0].Status != "ok" || results[0].Via != "" {
		t.Fatalf("expected direct fallback success, got %+v", results)
	}
}
