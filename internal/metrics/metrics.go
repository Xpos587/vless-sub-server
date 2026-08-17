// Package metrics renders the per-source subscription statistics collected by
// the pipeline as Prometheus text format for the internal VictoriaMetrics
// scrape. Nothing here contains upstream URLs or tokens — only aliases.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type SourceSeries struct {
	Alias          string
	FetchOK        bool
	Stale          bool
	ViaProxy       bool
	Lines          int
	Parsed         int
	Skipped        int
	Duplicates     int
	Unique         int
	AliveDirect    int
	AliveWarp      int
	CountryCounts  map[string]int
	ProtocolCounts map[string]int
}

type Snapshot struct {
	At      time.Time
	Sources []SourceSeries
}

func (s Snapshot) Render() []byte {
	var b strings.Builder
	gauges := []struct {
		name  string
		help  string
		value func(SourceSeries) int
	}{
		{"vlesssub_source_fetch_ok", "Whether the latest fetch of this source succeeded.", func(s SourceSeries) int { return boolInt(s.FetchOK) }},
		{"vlesssub_source_fetch_via_proxy", "Whether the source was fetched through the pool gateway after a direct failure.", func(s SourceSeries) int { return boolInt(s.ViaProxy) }},
		{"vlesssub_source_stale", "Whether the source is currently served from the stale cache.", func(s SourceSeries) int { return boolInt(s.Stale) }},
		{"vlesssub_source_lines", "Raw lines served by the source.", func(s SourceSeries) int { return s.Lines }},
		{"vlesssub_source_parsed", "Configs parsed from the source.", func(s SourceSeries) int { return s.Parsed }},
		{"vlesssub_source_skipped", "Unparseable lines in the source.", func(s SourceSeries) int { return s.Skipped }},
		{"vlesssub_source_duplicates", "Configs already contributed by an earlier source or repeated inside it.", func(s SourceSeries) int { return s.Duplicates }},
		{"vlesssub_source_unique", "Configs uniquely contributed by the source.", func(s SourceSeries) int { return s.Unique }},
		{"vlesssub_source_alive_direct", "Unique configs healthy on the direct path.", func(s SourceSeries) int { return s.AliveDirect }},
		{"vlesssub_source_alive_warp", "Unique configs healthy through the WARP chain.", func(s SourceSeries) int { return s.AliveWarp }},
		{"vlesssub_source_countries", "Distinct exit countries among WARP-healthy configs.", func(s SourceSeries) int { return len(s.CountryCounts) }},
	}
	for _, g := range gauges {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
		for _, source := range s.Sources {
			fmt.Fprintf(&b, "%s{source=%q} %d\n", g.name, source.Alias, g.value(source))
		}
	}

	fmt.Fprintf(&b, "# HELP vlesssub_source_country_configs WARP-healthy unique configs per exit country.\n# TYPE vlesssub_source_country_configs gauge\n")
	for _, source := range s.Sources {
		for _, country := range sortedKeys(source.CountryCounts) {
			fmt.Fprintf(&b, "vlesssub_source_country_configs{source=%q,country=%q} %d\n", source.Alias, country, source.CountryCounts[country])
		}
	}
	fmt.Fprintf(&b, "# HELP vlesssub_source_protocol_configs Unique configs per proxy protocol.\n# TYPE vlesssub_source_protocol_configs gauge\n")
	for _, source := range s.Sources {
		for _, protocol := range sortedKeys(source.ProtocolCounts) {
			fmt.Fprintf(&b, "vlesssub_source_protocol_configs{source=%q,protocol=%q} %d\n", source.Alias, protocol, source.ProtocolCounts[protocol])
		}
	}
	fmt.Fprintf(&b, "# HELP vlesssub_last_refresh_timestamp_seconds Unix time of the last published refresh.\n# TYPE vlesssub_last_refresh_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "vlesssub_last_refresh_timestamp_seconds %d\n", s.At.Unix())
	return []byte(b.String())
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func sortedKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
