package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestSnapshotRender(t *testing.T) {
	snapshot := Snapshot{
		At: time.Unix(1782300000, 0),
		ExitStats: []ExitStat{
			{Route: "direct", Kind: "ip_type", Value: "hosting", Count: 3},
			{Route: "warp", Kind: "risk_level", Value: "clean", Count: 2},
		},
		CoverageStats: []CoverageStat{
			{Checker: "port", Route: "direct", Eligible: 5, Fresh: 3, Stale: 1, Missing: 1},
		},
		CheckRuns: []CheckRunStat{
			{Checker: "port", LastCompletedAt: time.Unix(1782299900, 0)},
		},
		ProviderStats: []ProviderStat{{Provider: "proxycheck.io", Outcome: "quota", Count: 4}},
		ServiceStats: []ServiceStat{
			{Service: "gemini", Status: "unknown", Reason: "challenge", CacheState: "fresh", Route: "direct", Count: 2},
		},
		PortStats: []PortStat{
			{Port: 80, Status: "open", Route: "direct", Count: 1},
		},
		DNSBLStats: []DNSBLStat{
			{Zone: "zen.spamhaus.org", Status: "clean", Route: "warp", Count: 2},
		},
		Sources: []SourceSeries{
			{
				Alias:          "volnalink",
				FetchOK:        true,
				ViaProxy:       true,
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
		`vlesssub_source_fetch_via_proxy{source="volnalink"} 1`,
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
		`vlesssub_exit_ip_type{route="direct",type="hosting"} 3`,
		`vlesssub_exit_risk_level{route="warp",level="clean"} 2`,
		`vlesssub_check_exit_ips{checker="port",route="direct",state="eligible"} 5`,
		`vlesssub_check_exit_ips{checker="port",route="direct",state="fresh"} 3`,
		`vlesssub_check_exit_ips{checker="port",route="direct",state="stale"} 1`,
		`vlesssub_check_exit_ips{checker="port",route="direct",state="missing"} 1`,
		`vlesssub_check_last_completed_timestamp_seconds{checker="port"} 1782299900`,
		`vlesssub_ipintel_provider_requests_total{provider="proxycheck.io",outcome="quota"} 4`,
		`vlesssub_service_availability{service="gemini",status="unknown",reason="challenge",cache_state="fresh",route="direct"} 2`,
		`vlesssub_exit_port{port="80",status="open",route="direct"} 1`,
		`vlesssub_dnsbl{zone="zen.spamhaus.org",status="clean",route="warp"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("render missing %q in:\n%s", want, out)
		}
	}
}
