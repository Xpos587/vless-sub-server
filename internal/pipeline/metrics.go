package pipeline

import (
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/enrichment"
	"github.com/michael/vless-sub-server/internal/ipintel"
	"github.com/michael/vless-sub-server/internal/metrics"
	"github.com/michael/vless-sub-server/internal/servicecheck"
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

	portStats := buildPortStats(cached)
	dnsblStats := buildDNSBLStats(cached)
	return &metrics.Snapshot{At: at, Sources: series, ExitStats: buildExitStats(cached), CoverageStats: p.buildCoverageStats(cached), CheckRuns: p.buildCheckRuns(), ProviderStats: p.buildProviderStats(), ServiceStats: p.buildServiceStats(), PortStats: portStats, DNSBLStats: dnsblStats}
}

// refreshServiceMetrics updates only the service availability stats in the
// existing metrics snapshot, without rebuilding source stats.
func (p *Pipeline) refreshServiceMetrics() {
	snapshot, ok := p.MetricsSnapshot()
	if !ok {
		return
	}
	updated := *snapshot
	updated.ServiceStats = p.buildServiceStats()
	if cached, ok := p.Cached(); ok {
		updated.CoverageStats = p.buildCoverageStats(cached.Entries)
	}
	updated.CheckRuns = p.buildCheckRuns()
	updated.ProviderStats = p.buildProviderStats()
	p.metrics.Store(&updated)
}

func (p *Pipeline) refreshEnrichmentMetrics() {
	snapshot, ok := p.MetricsSnapshot()
	if !ok {
		return
	}
	cached, ok := p.Cached()
	if !ok {
		return
	}
	updated := *snapshot
	updated.ExitStats = buildExitStats(cached.Entries)
	updated.PortStats = buildPortStats(cached.Entries)
	updated.DNSBLStats = buildDNSBLStats(cached.Entries)
	updated.CoverageStats = p.buildCoverageStats(cached.Entries)
	updated.CheckRuns = p.buildCheckRuns()
	updated.ProviderStats = p.buildProviderStats()
	p.metrics.Store(&updated)
}

func (p *Pipeline) buildCoverageStats(cached []CachedEntry) []metrics.CoverageStat {
	direct, warp := routeExitIPs(cached)
	stats := make([]metrics.CoverageStat, 0, 8)
	if p.intelCache != nil {
		stats = append(stats, coverageStats("ipintel", "direct", p.intelCache, direct), coverageStats("ipintel", "warp", p.intelCache, warp))
	}
	if p.portCache != nil {
		stats = append(stats, coverageStats("port", "direct", p.portCache, direct), coverageStats("port", "warp", p.portCache, warp))
	}
	if p.dnsblCache != nil {
		stats = append(stats, coverageStats("dnsbl", "direct", p.dnsblCache, direct), coverageStats("dnsbl", "warp", p.dnsblCache, warp))
	}
	if p.serviceCache != nil {
		serviceNames := defaultServiceNames()
		directKeys := make([]servicecheck.RouteKey, 0, len(direct))
		warpKeys := make([]servicecheck.RouteKey, 0, len(warp))
		for _, ip := range direct {
			directKeys = append(directKeys, servicecheck.RouteKey{Route: "direct", IP: ip})
		}
		for _, ip := range warp {
			warpKeys = append(warpKeys, servicecheck.RouteKey{Route: "warp", IP: ip})
		}
		directCoverage := p.serviceCache.Coverage(directKeys, serviceNames)
		warpCoverage := p.serviceCache.Coverage(warpKeys, serviceNames)
		stats = append(stats,
			metrics.CoverageStat{Checker: "service", Route: "direct", Eligible: directCoverage.Eligible, Fresh: directCoverage.Fresh, Stale: directCoverage.Stale, Missing: directCoverage.Missing},
			metrics.CoverageStat{Checker: "service", Route: "warp", Eligible: warpCoverage.Eligible, Fresh: warpCoverage.Fresh, Stale: warpCoverage.Stale, Missing: warpCoverage.Missing},
		)
	}
	return stats
}

func defaultServiceNames() []string {
	checkers := servicecheck.DefaultCheckers()
	names := make([]string, 0, len(checkers))
	for _, checker := range checkers {
		names = append(names, checker.Name())
	}
	return names
}

func coverageStats[T any](checker, route string, cache *enrichment.Cache[T], ips []string) metrics.CoverageStat {
	coverage := cache.Coverage(ips)
	return metrics.CoverageStat{Checker: checker, Route: route, Eligible: coverage.Eligible, Fresh: coverage.Fresh, Stale: coverage.Stale, Missing: coverage.Missing}
}

func routeExitIPs(cached []CachedEntry) (direct, warp []string) {
	directSeen := map[string]struct{}{}
	warpSeen := map[string]struct{}{}
	for _, entry := range cached {
		if entry.DirectHealthy {
			ip := directExitIP(entry.Countries)
			if ip != "" {
				if _, ok := directSeen[ip]; !ok {
					directSeen[ip] = struct{}{}
					direct = append(direct, ip)
				}
			}
		}
		if entry.WarpHealthy {
			ip := warpExitIP(entry.Countries)
			if ip != "" {
				if _, ok := warpSeen[ip]; !ok {
					warpSeen[ip] = struct{}{}
					warp = append(warp, ip)
				}
			}
		}
	}
	return direct, warp
}

func (p *Pipeline) buildCheckRuns() []metrics.CheckRunStat {
	p.checkMu.RLock()
	defer p.checkMu.RUnlock()
	stats := make([]metrics.CheckRunStat, 0, len(p.checkRuns))
	for checker, at := range p.checkRuns {
		stats = append(stats, metrics.CheckRunStat{Checker: checker, LastCompletedAt: at})
	}
	return stats
}

func (p *Pipeline) buildProviderStats() []metrics.ProviderStat {
	if p.ipintel == nil {
		return nil
	}
	providerStats := p.ipintel.ProviderStats()
	stats := make([]metrics.ProviderStat, 0, len(providerStats))
	for _, stat := range providerStats {
		stats = append(stats, metrics.ProviderStat{Provider: stat.Provider, Outcome: string(stat.Outcome), Count: stat.Count})
	}
	return stats
}

func buildDNSBLStats(cached []CachedEntry) []metrics.DNSBLStat {
	type key struct{ route, zone, status string }
	counts := map[key]int{}
	seen := map[string]struct{}{}
	for _, entry := range cached {
		if entry.DirectHealthy {
			ip := directExitIP(entry.Countries)
			if _, ok := seen["direct|"+ip]; ip != "" && !ok {
				seen["direct|"+ip] = struct{}{}
				for _, result := range entry.DNSBLResults {
					counts[key{"direct", result.Zone, result.Status}]++
				}
			}
		}
		if entry.WarpHealthy {
			ip := warpExitIP(entry.Countries)
			if _, ok := seen["warp|"+ip]; ip != "" && !ok {
				seen["warp|"+ip] = struct{}{}
				for _, result := range entry.WarpDNSBLResults {
					counts[key{"warp", result.Zone, result.Status}]++
				}
			}
		}
	}
	stats := make([]metrics.DNSBLStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.DNSBLStat{Route: k.route, Zone: k.zone, Status: k.status, Count: count})
	}
	return stats
}

func buildPortStats(cached []CachedEntry) []metrics.PortStat {
	type key struct {
		route  string
		port   int
		status string
	}
	counts := map[key]int{}
	seen := map[string]struct{}{}
	for _, entry := range cached {
		if entry.DirectHealthy {
			ip := directExitIP(entry.Countries)
			if _, ok := seen["direct|"+ip]; ip != "" && !ok {
				seen["direct|"+ip] = struct{}{}
				for _, result := range entry.PortResults {
					counts[key{"direct", result.Port, string(result.Status)}]++
				}
			}
		}
		if entry.WarpHealthy {
			ip := warpExitIP(entry.Countries)
			if _, ok := seen["warp|"+ip]; ip != "" && !ok {
				seen["warp|"+ip] = struct{}{}
				for _, result := range entry.WarpPortResults {
					counts[key{"warp", result.Port, string(result.Status)}]++
				}
			}
		}
	}
	stats := make([]metrics.PortStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.PortStat{Route: k.route, Port: k.port, Status: k.status, Count: count})
	}
	return stats
}

func buildExitStats(cached []CachedEntry) []metrics.ExitStat {
	type key struct{ route, kind, value string }
	counts := map[key]int{}
	seen := map[string]struct{}{}
	add := func(route, ip string, intel *ipintel.Intel) {
		if ip == "" || intel == nil {
			return
		}
		seenKey := route + "|" + ip
		if _, ok := seen[seenKey]; ok {
			return
		}
		seen[seenKey] = struct{}{}
		counts[key{route, "ip_type", intel.Type}]++
		counts[key{route, "risk_level", intel.RiskLevel}]++
		flags := []struct {
			name    string
			enabled bool
		}{{"proxy", intel.Flags.Proxy}, {"vpn", intel.Flags.VPN}, {"tor", intel.Flags.Tor}, {"abuser", intel.Flags.Abuser}, {"datacenter", intel.Flags.Datacenter}, {"crawler", intel.Flags.Crawler}}
		for _, flag := range flags {
			if flag.enabled {
				counts[key{route, "reputation_flag", flag.name}]++
			}
		}
	}
	for _, entry := range cached {
		if entry.DirectHealthy {
			add("direct", directExitIP(entry.Countries), entry.Intel)
		}
		if entry.WarpHealthy {
			add("warp", warpExitIP(entry.Countries), entry.WarpIntel)
		}
	}
	stats := make([]metrics.ExitStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.ExitStat{Route: k.route, Kind: k.kind, Value: k.value, Count: count})
	}
	return stats
}

func (p *Pipeline) buildServiceStats() []metrics.ServiceStat {
	cached, ok := p.Cached()
	if !ok || p.serviceCache == nil {
		return nil
	}
	type key struct{ service, status, reason, cacheState, route string }
	counts := map[key]int{}
	direct, warp := routeExitIPs(cached.Entries)
	add := func(route string, ips []string) {
		for _, ip := range ips {
			results := p.serviceCache.Results(servicecheck.RouteKey{Route: route, IP: ip})
			for _, cachedResult := range results {
				result := cachedResult.Result
				counts[key{result.Service, string(result.Status), servicecheck.ResultReason(result), string(cachedResult.State), route}]++
			}
		}
	}
	add("direct", direct)
	add("warp", warp)
	stats := make([]metrics.ServiceStat, 0, len(counts))
	for k, count := range counts {
		stats = append(stats, metrics.ServiceStat{Service: k.service, Status: k.status, Reason: k.reason, CacheState: k.cacheState, Route: k.route, Count: count})
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
