package pipeline

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/parse"
)

func mustParseLine(t *testing.T, line string) *parse.ProxyRecord {
	t.Helper()
	result := parse.ParseAllLines([]string{line})
	if len(result.Records) != 1 {
		t.Fatalf("line did not parse: %q", line)
	}
	return &result.Records[0]
}

func TestAttributeSourcesFirstSourceWins(t *testing.T) {
	shared := "vless://uuid-a@shared.example.com:443?security=reality&sni=a.com#shared"
	merged := []fetch.MergedSource{
		{URL: "https://a.example/sub", FetchOK: true, ViaProxy: true, Lines: []string{
			shared,
			"vless://uuid-b@a1.example.com:443?security=reality&sni=a.com#a1",
			"# comment",
			"not-a-proxy",
		}},
		{URL: "https://b.example/sub", FetchOK: true, Lines: []string{
			shared, // cross-source duplicate of source 0
			shared, // duplicate within source 1 as well
			"trojan://pw@b1.example.com:443?security=tls&sni=b.com#b1",
		}},
		{URL: "https://c.example/sub", FetchOK: false, Stale: true, Lines: []string{
			"hysteria2://pw@c1.example.com:443?sni=c.com#c1",
		}},
	}

	sources, owners := AttributeSources(merged)
	if len(sources) != 3 {
		t.Fatalf("sources = %d", len(sources))
	}

	a := sources[0]
	if !a.FetchOK || !a.ViaProxy || a.Lines != 4 || a.Parsed != 2 || a.Skipped != 2 || a.Duplicates != 0 || a.Unique != 2 {
		t.Fatalf("source a wrong: %+v", a)
	}
	b := sources[1]
	if b.Parsed != 2 || b.Duplicates != 2 || b.Unique != 1 {
		t.Fatalf("source b wrong: %+v", b)
	}
	c := sources[2]
	if c.FetchOK || !c.Stale || c.Unique != 1 {
		t.Fatalf("source c wrong: %+v", c)
	}

	if len(owners) != 4 {
		t.Fatalf("owners = %d, want 4 unique records", len(owners))
	}
	for line, wantSource := range map[string]int{
		shared: 0,
		"vless://uuid-b@a1.example.com:443?security=reality&sni=a.com#a1": 0,
		"trojan://pw@b1.example.com:443?security=tls&sni=b.com#b1":        1,
		"hysteria2://pw@c1.example.com:443?sni=c.com#c1":                  2,
	} {
		record := mustParseLine(t, line)
		idx, ok := owners[identity(*record)]
		if !ok || idx != wantSource {
			t.Fatalf("owner of %q = %d/%t, want %d", line, idx, ok, wantSource)
		}
	}
}
