package pipeline

import (
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/metrics"
)

// MetricsSnapshot returns the last published per-source statistics snapshot.
func (p *Pipeline) MetricsSnapshot() (*metrics.Snapshot, bool) {
	v := p.metrics.Load()
	if v == nil {
		return nil, false
	}
	return v.(*metrics.Snapshot), true
}

func (p *Pipeline) buildMetricsSnapshot(at time.Time, attributions []SourceAttribution, owners map[string]int, entries []outputEntry, cached []CachedEntry) *metrics.Snapshot {
	series := make([]metrics.SourceSeries, len(attributions))
	for i, attr := range attributions {
		series[i] = metrics.SourceSeries{
			Alias:          p.cfg.SourceAlias(i),
			FetchOK:        attr.FetchOK,
			Stale:          attr.Stale,
			ViaProxy:       attr.ViaProxy,
			Lines:          attr.Lines,
			Parsed:         attr.Parsed,
			Skipped:        attr.Skipped,
			Duplicates:     attr.Duplicates,
			Unique:         attr.Unique,
			CountryCounts:  map[string]int{},
			ProtocolCounts: map[string]int{},
		}
	}

	for i, entry := range entries {
		owner, ok := owners[identity(entry.Record)]
		if !ok {
			continue
		}
		series[owner].ProtocolCounts[string(entry.Record.Protocol)]++
		if cached[i].DirectHealthy {
			series[owner].AliveDirect++
		}
		if cached[i].WarpHealthy {
			series[owner].AliveWarp++
			series[owner].CountryCounts[exitCountry(entry.Countries)]++
		}
	}

	stats := metrics.IPIntelStats{
		TypeCounts: map[string]int{},
		RiskCounts: map[string]int{},
		FlagCounts: map[string]int{},
	}
	for _, entry := range cached {
		if entry.Intel == nil {
			continue
		}
		stats.TypeCounts[entry.Intel.Type]++
		stats.RiskCounts[entry.Intel.RiskLevel]++
		if entry.Intel.Flags.Proxy {
			stats.FlagCounts["proxy"]++
		}
		if entry.Intel.Flags.VPN {
			stats.FlagCounts["vpn"]++
		}
		if entry.Intel.Flags.Tor {
			stats.FlagCounts["tor"]++
		}
		if entry.Intel.Flags.Abuser {
			stats.FlagCounts["abuser"]++
		}
		if entry.Intel.Flags.Datacenter {
			stats.FlagCounts["datacenter"]++
		}
		if entry.Intel.Flags.Crawler {
			stats.FlagCounts["crawler"]++
		}
	}

	portStats := buildPortStats(cached)
	return &metrics.Snapshot{At: at, Sources: series, IPIntel: stats, ServiceStats: buildServiceStats(cached), PortStats: portStats}
}

func buildPortStats(cached []CachedEntry) []metrics.PortStat {
	type key struct{ port int; status string }
	counts := map[key]int{}
	for _, entry := range cached {
		for _, result := range entry.PortResults {
			counts[key{result.Port, string(result.Status)}]++
		}
		for _, result := range entry.WarpPortResults {
			counts[key{result.Port, string(result.Status)}]++
		}
	}
	stats := make([]metrics.PortStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.PortStat{Port: k.port, Status: k.status, Count: count})
	}
	return stats
}

func buildServiceStats(cached []CachedEntry) []metrics.ServiceStat {
	type key struct{ service, status, route string }
	counts := map[key]int{}
	for _, entry := range cached {
		for _, result := range entry.Services {
			counts[key{result.Service, string(result.Status), "direct"}]++
		}
		for _, result := range entry.WarpServices {
			counts[key{result.Service, string(result.Status), "warp"}]++
		}
	}
	stats := make([]metrics.ServiceStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.ServiceStat{Service: k.service, Status: k.status, Route: k.route, Count: count})
	}
	return stats
}

// exitCountry picks the country a WARP-chain user actually exits from,
// falling back to the direct observation and finally to "unknown".
func exitCountry(countries country.RouteCountries) string {
	for _, candidate := range []string{
		countries.WarpV4.ObservedCountry,
		countries.WarpV4.Country,
		countries.WarpV6.ObservedCountry,
		countries.WarpV6.Country,
		countries.DirectV4.ObservedCountry,
		countries.DirectV4.Country,
	} {
		if candidate != "" {
			return candidate
		}
	}
	return "unknown"
}
