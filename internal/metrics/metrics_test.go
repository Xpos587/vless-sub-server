package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestSnapshotRender(t *testing.T) {
	snapshot := Snapshot{
		At: time.Unix(1782300000, 0),
		Sources: []SourceSeries{
			{
				Alias:          "volnalink",
				FetchOK:        true,
				Lines:          120,
				Parsed:         110,
				Skipped:        10,
				Duplicates:     60,
				Unique:         50,
				AliveDirect:    40,
				AliveWarp:      35,
				CountryCounts:  map[string]int{"NL": 20, "GB": 15},
				ProtocolCounts: map[string]int{"vless": 45, "trojan": 5},
			},
			{
				Alias:          "dead`\"source",
				FetchOK:        false,
				Stale:          true,
				CountryCounts:  map[string]int{},
				ProtocolCounts: map[string]int{},
			},
		},
	}

	out := string(snapshot.Render())
	for _, want := range []string{
		`vlesssub_source_fetch_ok{source="volnalink"} 1`,
		`vlesssub_source_stale{source="volnalink"} 0`,
		`vlesssub_source_lines{source="volnalink"} 120`,
		`vlesssub_source_parsed{source="volnalink"} 110`,
		`vlesssub_source_skipped{source="volnalink"} 10`,
		`vlesssub_source_duplicates{source="volnalink"} 60`,
		`vlesssub_source_unique{source="volnalink"} 50`,
		`vlesssub_source_alive_direct{source="volnalink"} 40`,
		`vlesssub_source_alive_warp{source="volnalink"} 35`,
		`vlesssub_source_countries{source="volnalink"} 2`,
		`vlesssub_source_country_configs{source="volnalink",country="NL"} 20`,
		`vlesssub_source_country_configs{source="volnalink",country="GB"} 15`,
		`vlesssub_source_protocol_configs{source="volnalink",protocol="trojan"} 5`,
		"vlesssub_source_fetch_ok{source=\"dead`\\\"source\"} 0",
		"vlesssub_source_stale{source=\"dead`\\\"source\"} 1",
		`vlesssub_last_refresh_timestamp_seconds 1782300000`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q in:\n%s", want, out)
		}
	}
}
