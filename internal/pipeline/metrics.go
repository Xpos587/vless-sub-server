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

	return &metrics.Snapshot{At: at, Sources: series}
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
