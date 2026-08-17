package pipeline

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

func fallbackEntry(host string, direct, warp bool) CachedEntry {
	return CachedEntry{
		Entry: rename.RenamedEntry{
			Record: parse.ProxyRecord{
				Protocol: parse.VLESS, Host: host, Port: 443, UUIDOrPassword: "u",
				QueryParams: map[string]string{"type": "tcp"},
			},
			RenamedFragment: host,
		},
		DirectHealthy: direct,
		WarpHealthy:   warp,
	}
}

func TestGatewayCandidatesPicksDistinctDirectHealthy(t *testing.T) {
	p := &Pipeline{}
	p.cache.Store(&CachedData{Entries: []CachedEntry{
		fallbackEntry("dead.example", false, true),
		fallbackEntry("a.example", true, false),
		fallbackEntry("b.example", true, true),
		fallbackEntry("c.example", true, true),
		fallbackEntry("d.example", true, true),
	}})

	candidates := p.gatewayCandidates(3)
	if len(candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(candidates))
	}
	for _, record := range candidates {
		if record.Host == "dead.example" {
			t.Fatal("direct-unhealthy record selected")
		}
	}
}

func TestGatewayCandidatesEmptyWithoutCache(t *testing.T) {
	p := &Pipeline{}
	if got := p.gatewayCandidates(3); len(got) != 0 {
		t.Fatalf("candidates = %d without cache", len(got))
	}
}
