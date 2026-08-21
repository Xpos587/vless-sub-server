// Package pipeline composes fetching, probing, quality state, and publication.
package pipeline

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/dnsbl"
	"github.com/michael/vless-sub-server/internal/endpointgeo"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/ipintel"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/portcheck"
	"github.com/michael/vless-sub-server/internal/quality"
	"github.com/michael/vless-sub-server/internal/rename"
	"github.com/michael/vless-sub-server/internal/servicecheck"
)

type CachedData struct {
	Output      string
	JSONOutput  []byte
	Entries     []CachedEntry
	Metadata    format.FormatMetadata
	LastRefresh time.Time
}

type CachedEntry struct {
	Entry         rename.RenamedEntry
	WarpEntry     rename.RenamedEntry
	Countries     country.RouteCountries
	DirectHealthy bool
	WarpHealthy   bool
	Intel         *ipintel.Intel
	WarpIntel     *ipintel.Intel
	Services      []servicecheck.Result
	WarpServices  []servicecheck.Result
	PortResults   []portcheck.PortResult
	WarpPortResults []portcheck.PortResult
	DNSBLResults    []dnsbl.Result
	WarpDNSBLResults []dnsbl.Result
}

type outputEntry struct {
	Record    parse.ProxyRecord
	Geo       *geo.GeoInfo
	WarpGeo   *geo.GeoInfo
	IsLAN     bool
	Countries country.RouteCountries
	Intel     *ipintel.Intel
	WarpIntel *ipintel.Intel
	Services     []servicecheck.Result
	WarpServices []servicecheck.Result
	PortResults   []portcheck.PortResult
	WarpPortResults []portcheck.PortResult
	DNSBLResults    []dnsbl.Result
	WarpDNSBLResults []dnsbl.Result
}

type RefreshResult struct {
	Published                                bool
	Parsed, Resolved                         int
	Good, Partial, Dead                      int
	BandwidthCandidates, BandwidthSuccesses  int
	CountryStateSaveFailed                   bool
	DirectCountrySources, WarpCountrySources map[string]int
}

type CountryReprobeResult struct {
	Candidates, Updated    int
	CountryStateSaveFailed bool
	WarpCountrySources     map[string]int
}

type Pipeline struct {
	cfg          *config.Config
	dnsCache     *dns.DNSCache
	sourceCache  *fetch.SourceCache
	runtime      *quality.Store
	countryState *country.StateStore
	cache        atomic.Value // stores *CachedData
	metrics      atomic.Value // stores *metrics.Snapshot
	refreshMu    sync.Mutex   // Refresh and country-only reprobes share mutable runtime state.
	ipintel      *ipintel.Aggregator
	serviceCache *servicecheck.Cache
}

const (
	bandwidthStageTimeout    = 30 * time.Second
	endpointGeoLookupTimeout = 8 * time.Second
)

func New(cfg *config.Config, dnsCache *dns.DNSCache) *Pipeline {
	state, _ := country.OpenStateStore("")
	p := &Pipeline{cfg: cfg, dnsCache: dnsCache, sourceCache: fetch.NewSourceCache(), runtime: quality.NewStore(), countryState: state}
	if cfg.IPIntelEnabled {
		providers := ipintel.DefaultProviders(cfg.IPIntelTimeout)
		if cfg.IPIntelCheckPlace && cfg.IPIntelProxyURL != "" {
			if transport, err := fetch.Socks5Transport(cfg.IPIntelProxyURL, cfg.IPIntelTimeout); err == nil {
				providers = append(providers, ipintel.NewCheckPlace(&http.Client{Transport: transport, Timeout: cfg.IPIntelTimeout}))
			}
		}
		p.ipintel = ipintel.NewAggregator(providers, cfg.IPIntelCacheTTL)
	}
	if cfg.ServiceCheckEnabled {
		p.serviceCache = servicecheck.NewCache(cfg.ServiceCheckCacheTTL)
	}
	return p
}

// LoadCountryState enables durable country evidence before the first refresh.
func (p *Pipeline) LoadCountryState(path string) error {
	state, err := country.OpenStateStore(path)
	if err != nil {
		return err
	}
	p.countryState = state
	return nil
}

func (p *Pipeline) Cached() (*CachedData, bool) {
	v := p.cache.Load()
	if v == nil {
		return nil, false
	}
	data := *(v.(*CachedData))
	data.JSONOutput = append([]byte(nil), data.JSONOutput...)
	data.Entries = cloneCachedEntries(data.Entries)
	return &data, true
}

func CanPublish(entryCount int, _ bool) bool { return entryCount > 0 }

func StateRank(state string) int {
	switch quality.State(state) {
	case quality.Healthy:
		return 0
	case quality.Recovering:
		return 1
	case quality.Degraded:
		return 2
	default:
		return 3
	}
}

func (p *Pipeline) Refresh(ctx context.Context) RefreshResult {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	now := time.Now()
	result := RefreshResult{DirectCountrySources: make(map[string]int), WarpCountrySources: make(map[string]int)}
	fetched := p.fetchAllSources(ctx)
	fetched = p.retryFailedFetchesViaPool(ctx, fetched)
	merged := p.sourceCache.MergeDetailed(now, fetched, p.cfg.SourceStaleMaxAge)
	attributions, owners := AttributeSources(merged)
	var lines []string
	for _, source := range merged {
		lines = append(lines, source.Lines...)
	}
	parsed := parse.ParseAllLines(lines)
	filtered := parse.ApplyNameFilter(parsed.Records, p.cfg.NameInclude, p.cfg.NameExclude)
	result.Parsed = len(filtered)

	dnsMap := dns.ResolveHosts(ctx, dedupHosts(filtered), 20, p.cfg.DNSTimeout, p.dnsCache)
	p.attachEndpointGeo(ctx, dnsMap)
	probed := make([]parse.ProxyRecord, 0, len(filtered))
	for _, record := range filtered {
		if resolved := dnsMap[record.Host]; resolved != nil && resolved.IP != "" {
			probed = append(probed, record)
		}
	}
	result.Resolved = len(probed)
	if len(probed) == 0 {
		return result
	}

	ep := exitprobe.NewExitProber(p.cfg)
	if ep.StartWithProxies(probed) != nil {
		return result
	}
	defer ep.Stop()
	probes := ep.ProbeAll(ctx, probed)
	for _, probe := range probes {
		if probe == nil {
			result.DirectCountrySources["none"]++
			result.WarpCountrySources["none"]++
			continue
		}
		result.DirectCountrySources[probe.DirectSource]++
		result.WarpCountrySources[probe.WarpSource]++
	}
	if !hasReachabilityWitness(probes) {
		return result // The shared measurement path failed; preserve prior state and cache.
	}

	active := make(map[string]int, len(probed))
	for i, record := range probed {
		key := identity(record)
		active[key] = i
		p.updateRuntime(key, probes[i], now)
	}

	bandwidth := quality.DefaultBandwidthConfig()
	bandwidth.BytesPerProbe = p.cfg.BandwidthBytes
	bandwidth.BudgetBytes = p.cfg.BandwidthBudget
	bandwidth.RefreshAfter = p.cfg.BandwidthRefreshAfter
	bandwidth.RetryAfter = p.cfg.BandwidthRetryAfter
	if p.cfg.BandwidthEnabled {
		selected := quality.SelectBandwidthCandidates(p.activeRuntime(active), now, bandwidth)
		indices := make([]int, 0, len(selected))
		keys := make(map[int]string, len(selected))
		for _, runtime := range selected {
			index := active[runtime.Key]
			indices = append(indices, index)
			keys[index] = runtime.Key
		}
		result.BandwidthCandidates = len(indices)
		bandwidthCtx, cancel := context.WithTimeout(ctx, bandwidthStageTimeout)
		measurements := ep.ProbeBandwidth(bandwidthCtx, indices)
		cancel()
		for index, mbps := range measurements {
			p.updateBandwidth(keys[index], mbps, now)
			result.BandwidthSuccesses++
		}
		for _, key := range keys {
			p.markBandwidthAttempt(key, now)
		}
	}

	intelByIP := p.enrichExitIntel(ctx, probed, probes)
	portByIP := p.checkPorts(ctx, probes)
	dnsblByIP := p.checkDNSBL(ctx, probes)
	entries, geoAvailable := p.outputEntries(probed, probes, dnsMap, intelByIP, portByIP, dnsblByIP, &result)
	hasExisting := p.cache.Load() != nil
	if !CanPublish(len(entries), hasExisting) {
		return result
	}
	renameInput := make([]struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}, len(entries))
	warpRenameInput := make([]struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}, len(entries))
	for i, entry := range entries {
		renameInput[i] = struct {
			Record parse.ProxyRecord
			Geo    *geo.GeoInfo
			IsLAN  bool
		}{entry.Record, entry.Geo, entry.IsLAN}
		warpRenameInput[i] = struct {
			Record parse.ProxyRecord
			Geo    *geo.GeoInfo
			IsLAN  bool
		}{entry.Record, entry.WarpGeo, entry.IsLAN}
	}
	renamed := rename.RenameAll(renameInput)
	warpRenamed := rename.RenameAll(warpRenameInput)
	sourcesOK := 0
	for _, source := range fetched {
		if source.Status == "ok" {
			sourcesOK++
		}
	}
	meta := format.FormatMetadata{TotalFetched: len(lines), TotalParsed: len(filtered), TotalSkipped: parsed.Skipped, TotalDuplicates: parsed.Duplicates, TotalAlive: len(renamed), TotalDead: result.Dead, SourcesOK: sourcesOK, SourcesFailed: len(fetched) - sourcesOK, GeoAvailable: geoAvailable, GeoTotal: len(probed)}
	cachedEntries := make([]CachedEntry, len(renamed))
	directEntries := make([]rename.RenamedEntry, 0, len(renamed))
	warpEntries := make([]rename.RenamedEntry, 0, len(renamed))
	for i, entry := range renamed {
		runtime, _ := p.runtime.Get(identity(entries[i].Record))
		cachedEntries[i] = CachedEntry{
			Entry:         cloneRenamedEntry(entry),
			WarpEntry:     cloneRenamedEntry(warpRenamed[i]),
			Countries:     entries[i].Countries,
			DirectHealthy: runtime.DirectHealthy,
			WarpHealthy:   runtime.WarpHealthy,
			Intel:         cloneIntel(entries[i].Intel),
			WarpIntel:     cloneIntel(entries[i].WarpIntel),
			Services:      append([]servicecheck.Result(nil), entries[i].Services...),
			WarpServices:  append([]servicecheck.Result(nil), entries[i].WarpServices...),
			PortResults:     append([]portcheck.PortResult(nil), entries[i].PortResults...),
			WarpPortResults: append([]portcheck.PortResult(nil), entries[i].WarpPortResults...),
			DNSBLResults:      append([]dnsbl.Result(nil), entries[i].DNSBLResults...),
			WarpDNSBLResults:  append([]dnsbl.Result(nil), entries[i].WarpDNSBLResults...),
		}
		if runtime.DirectHealthy {
			directEntries = append(directEntries, entry)
		}
		if runtime.WarpHealthy {
			warpEntries = append(warpEntries, warpRenamed[i])
		}
	}
	directMeta, warpMeta := meta, meta
	directMeta.TotalAlive, warpMeta.TotalAlive = len(directEntries), len(warpEntries)
	p.cache.Store(&CachedData{Entries: cachedEntries, Metadata: meta, Output: format.FormatOutput(directEntries, directMeta), JSONOutput: format.FormatXrayJSON(warpEntries, warpMeta), LastRefresh: now})
	p.metrics.Store(p.buildMetricsSnapshot(now, attributions, owners, entries, cachedEntries))
	if p.countryState != nil {
		if err := p.countryState.Save(); err != nil {
			result.CountryStateSaveFailed = true
		}
	}
	result.Published = true
	p.dnsCache.Purge()
	return result
}

// ReprobeWarpCountries refreshes unresolved final WARP egress evidence without
// fetching subscriptions or running direct-health and bandwidth probes.
func (p *Pipeline) ReprobeWarpCountries(ctx context.Context) CountryReprobeResult {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()

	result := CountryReprobeResult{WarpCountrySources: make(map[string]int)}
	cached, ok := p.Cached()
	if !ok {
		return result
	}
	candidates := selectWarpReprobeCandidates(cached.Entries)
	result.Candidates = len(candidates)
	if len(candidates) == 0 {
		return result
	}

	ep := exitprobe.NewExitProber(p.cfg)
	if ep.StartWithProxies(candidates) != nil {
		return result
	}
	defer ep.Stop()
	probes := ep.ProbeWarpCountries(ctx, candidates)
	now := time.Now()
	changed := false
	for index, record := range candidates {
		probe := probes[index]
		result.WarpCountrySources[probe.Source]++
		key := identity(record)
		runtime, exists := p.runtime.Get(key)
		if !exists {
			continue
		}
		previous := runtime.Countries
		runtime.Countries = country.Apply(runtime.Countries, true, probe.Country, now)
		if runtime.Countries == previous {
			continue
		}
		p.runtime.Set(runtime)
		if p.countryState != nil {
			p.countryState.Set(key, runtime.Countries)
		}
		result.Updated++
		changed = true
	}
	if changed {
		p.rebuildCachedCountries(cached)
	}
	if p.countryState != nil && changed {
		if err := p.countryState.Save(); err != nil {
			result.CountryStateSaveFailed = true
		}
	}
	return result
}

func (p *Pipeline) rebuildCachedCountries(cached *CachedData) {
	entries := cloneCachedEntries(cached.Entries)
	directEntries := make([]rename.RenamedEntry, 0, len(entries))
	warpEntries := make([]rename.RenamedEntry, 0, len(entries))
	for index := range entries {
		runtime, ok := p.runtime.Get(identity(entries[index].Entry.Record))
		if !ok {
			continue
		}
		entries[index].Countries = runtime.Countries
		entries[index].DirectHealthy = runtime.DirectHealthy
		entries[index].WarpHealthy = runtime.WarpHealthy
		if runtime.DirectHealthy {
			directEntries = append(directEntries, entries[index].Entry)
		}
		if runtime.WarpHealthy {
			entry := entries[index].WarpEntry
			if entry.Record.Protocol == "" {
				entry = entries[index].Entry
			}
			warpEntries = append(warpEntries, entry)
		}
	}
	directMeta, warpMeta := cached.Metadata, cached.Metadata
	directMeta.TotalAlive, warpMeta.TotalAlive = len(directEntries), len(warpEntries)
	p.cache.Store(&CachedData{Entries: entries, Metadata: cached.Metadata, Output: format.FormatOutput(directEntries, directMeta), JSONOutput: format.FormatXrayJSON(warpEntries, warpMeta), LastRefresh: cached.LastRefresh})
}

func (p *Pipeline) updateRuntime(key string, probe *exitprobe.ExitProbeResult, now time.Time) {
	previous, exists := p.runtime.Get(key)
	if !exists && p.countryState != nil {
		if countries, found := p.countryState.Get(key); found {
			previous.Countries = countries
		}
	}
	metrics := quality.Metrics{}
	if probe != nil {
		metrics = probe.Metrics
	}
	directHealthy := metrics.InternetReachable
	warpHealthy := probe != nil && probe.WarpCountry.Valid()
	observation := quality.Blackhole
	if metrics.SuccessCount*5 >= metrics.SampleCount*4 && metrics.SampleCount > 0 {
		observation = quality.Good
	} else if directHealthy || warpHealthy {
		observation = quality.Partial
	}
	state := previous.StateData
	if !exists {
		state.State = quality.Healthy
	}
	state = quality.Transition(state, observation, now, quality.DefaultStateConfig())
	runtime := previous
	runtime.Key, runtime.State, runtime.StateData = key, state.State, state
	runtime.DirectHealthy, runtime.WarpHealthy, runtime.Reachable = directHealthy, warpHealthy, directHealthy || warpHealthy
	if directHealthy {
		if previous.Metrics.BandwidthMeasured {
			metrics.DownloadMbps = previous.Metrics.DownloadMbps
			metrics.BandwidthMeasured = true
			metrics.BandwidthFresh = previous.Metrics.BandwidthFresh && now.Sub(previous.LastBandwidthSuccessAt) < p.cfg.BandwidthRefreshAfter
		}
		raw, ewma := quality.Score(metrics, previous.ScoreEWMA, previous.HasScore, now, quality.DefaultScoringConfig())
		runtime.Metrics, runtime.RawScore, runtime.ScoreEWMA, runtime.HasScore, runtime.LastSuccessfulAt = metrics, raw, ewma, true, now
	}
	if probe != nil && probe.GeoInfo != nil {
		runtime.GeoInfo = cloneGeo(probe.GeoInfo)
	}
	if probe != nil && probe.WarpGeoInfo != nil {
		runtime.WarpGeoInfo = cloneGeo(probe.WarpGeoInfo)
	}
	if probe != nil {
		runtime.Countries = country.Apply(runtime.Countries, false, probe.DirectCountry, now)
		runtime.Countries = country.Apply(runtime.Countries, true, probe.WarpCountry, now)
	}
	p.runtime.Set(runtime)
	if p.countryState != nil {
		p.countryState.Set(key, runtime.Countries)
	}
}

func (p *Pipeline) activeRuntime(active map[string]int) []quality.Runtime {
	all := p.runtime.Snapshot()
	current := make([]quality.Runtime, 0, len(active))
	for _, runtime := range all {
		if _, ok := active[runtime.Key]; ok {
			current = append(current, runtime)
		}
	}
	return current
}

func (p *Pipeline) updateBandwidth(key string, mbps float64, now time.Time) {
	runtime, ok := p.runtime.Get(key)
	if !ok {
		return
	}
	runtime.Metrics.DownloadMbps, runtime.Metrics.BandwidthMeasured, runtime.Metrics.BandwidthFresh = mbps, true, true
	runtime.LastBandwidthSuccessAt = now
	if runtime.HasScore {
		runtime.RawScore, runtime.ScoreEWMA = quality.Score(runtime.Metrics, runtime.ScoreEWMA, true, now, quality.DefaultScoringConfig())
	}
	p.runtime.Set(runtime)
}

func (p *Pipeline) markBandwidthAttempt(key string, now time.Time) {
	runtime, ok := p.runtime.Get(key)
	if !ok {
		return
	}
	runtime.LastBandwidthAttemptAt = now
	p.runtime.Set(runtime)
}

func (p *Pipeline) outputEntries(records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult, dnsMap map[string]*dns.DNSResult, intelByIP map[string]*ipintel.Intel, portByIP map[string][]portcheck.PortResult, dnsblByIP map[string][]dnsbl.Result, result *RefreshResult) ([]outputEntry, int) {
	type item struct {
		record  parse.ProxyRecord
		runtime quality.Runtime
		geo     *geo.GeoInfo
		lan     bool
		probe   *exitprobe.ExitProbeResult
		services []servicecheck.Result
		warpServices []servicecheck.Result
		ports    []portcheck.PortResult
		warpPorts []portcheck.PortResult
		dnsbl    []dnsbl.Result
		warpDNSBL []dnsbl.Result
	}
	items := make([]item, 0, len(records))
	geoAvailable := 0
	for i, record := range records {
		runtime, ok := p.runtime.Get(identity(record))
		if !ok || runtime.State == quality.Dead {
			result.Dead++
			continue
		}
		if runtime.State == quality.Healthy {
			result.Good++
		} else {
			result.Partial++
		}
		info := runtime.GeoInfo
		if info == nil {
			info = dnsMap[record.Host].EndpointGeo
		}
		if info != nil {
			geoAvailable++
		}
		var probe *exitprobe.ExitProbeResult
		if probes != nil {
			probe = probes[i]
		}
		items = append(items, item{
			record:       record,
			runtime:       runtime,
			geo:          info,
			lan:          dnsMap[record.Host].IsPrivate,
			probe:        probe,
			services:     p.serviceResults(directIP(probe)),
			warpServices: p.serviceResults(warpIP(probe)),
			ports:        portByIP[directIP(probe)],
			warpPorts:    portByIP[warpIP(probe)],
			dnsbl:        dnsblByIP[directIP(probe)],
			warpDNSBL:    dnsblByIP[warpIP(probe)],
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		left, right := items[i].runtime, items[j].runtime
		if StateRank(string(left.State)) != StateRank(string(right.State)) {
			return StateRank(string(left.State)) < StateRank(string(right.State))
		}
		return left.ScoreEWMA < right.ScoreEWMA
	})
	entries := make([]outputEntry, 0, len(items))
	for _, item := range items {
		var intel, warpIntel *ipintel.Intel
		if item.probe != nil {
			if item.probe.DirectCountry.Valid() {
				intel = intelByIP[item.probe.DirectCountry.IP.String()]
			}
			if item.probe.WarpCountry.Valid() {
				warpIntel = intelByIP[item.probe.WarpCountry.IP.String()]
			}
		}
		entries = append(entries, outputEntry{
			Record:    item.record,
			Geo:       item.geo,
			WarpGeo:   cloneGeo(item.runtime.WarpGeoInfo),
			IsLAN:     item.lan,
			Countries: item.runtime.Countries,
			Intel:     intel,
			WarpIntel: warpIntel,
			Services:     item.services,
			WarpServices: item.warpServices,
			PortResults:   item.ports,
			WarpPortResults: item.warpPorts,
			DNSBLResults:    item.dnsbl,
			WarpDNSBLResults: item.warpDNSBL,
		})
	}
	return entries, geoAvailable
}

func hasReachabilityWitness(probes map[int]*exitprobe.ExitProbeResult) bool {
	for _, probe := range probes {
		if probe != nil && (probe.Metrics.InternetReachable || probe.WarpCountry.Valid()) {
			return true
		}
	}
	return false
}
func identity(record parse.ProxyRecord) string {
	return quality.Identity(string(record.Protocol), record.Host, record.Port, record.UUIDOrPassword, record.QueryParams)
}
func dedupHosts(records []parse.ProxyRecord) []string {
	seen := make(map[string]bool, len(records))
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		if !seen[record.Host] {
			seen[record.Host] = true
			hosts = append(hosts, record.Host)
		}
	}
	return hosts
}

func (p *Pipeline) attachEndpointGeo(ctx context.Context, dnsMap map[string]*dns.DNSResult) {
	ips := make([]string, 0, len(dnsMap))
	seen := make(map[string]struct{}, len(dnsMap))
	for _, resolved := range dnsMap {
		if resolved == nil || resolved.IP == "" || resolved.IsPrivate {
			continue
		}
		if _, exists := seen[resolved.IP]; !exists {
			seen[resolved.IP] = struct{}{}
			ips = append(ips, resolved.IP)
		}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, endpointGeoLookupTimeout)
	defer cancel()
	byIP := endpointgeo.LookupAll(lookupCtx, ips, 20, endpointGeoLookupTimeout)
	for _, resolved := range dnsMap {
		if resolved != nil {
			resolved.EndpointGeo = cloneGeo(byIP[resolved.IP])
		}
	}
}
func cloneGeo(info *geo.GeoInfo) *geo.GeoInfo {
	if info == nil {
		return nil
	}
	copy := *info
	return &copy
}

func cloneIntel(info *ipintel.Intel) *ipintel.Intel {
	if info == nil {
		return nil
	}
	copy := *info
	if info.Sources != nil {
		copy.Sources = append([]string(nil), info.Sources...)
	}
	return &copy
}

func directIP(probe *exitprobe.ExitProbeResult) string {
	if probe != nil && probe.DirectCountry.Valid() {
		return probe.DirectCountry.IP.String()
	}
	return ""
}

// serviceResults returns cached service-check results for an exit IP, or nil
// if service checks are disabled or no results are cached yet.
func (p *Pipeline) serviceResults(ip string) []servicecheck.Result {
	if p.serviceCache == nil || ip == "" {
		return nil
	}
	results, ok := p.serviceCache.Get(ip)
	if !ok {
		return nil
	}
	return results
}

func warpIP(probe *exitprobe.ExitProbeResult) string {
	if probe != nil && probe.WarpCountry.Valid() {
		return probe.WarpCountry.IP.String()
	}
	return ""
}

// enrichExitIntel looks up reputation for each unique direct and WARP exit IP.
// It is a no-op when IP intelligence is disabled. The returned map is keyed by
// exit IP string; callers attribute it to direct or WARP routes by probe IP.
func (p *Pipeline) enrichExitIntel(ctx context.Context, records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult) map[string]*ipintel.Intel {
	byIP := make(map[string]*ipintel.Intel)
	if p.ipintel == nil {
		return byIP
	}
	unique := make(map[string]netip.Addr)
	for _, probe := range probes {
		if probe == nil {
			continue
		}
		if probe.DirectCountry.Valid() {
			unique[probe.DirectCountry.IP.String()] = probe.DirectCountry.IP
		}
		if probe.WarpCountry.Valid() {
			unique[probe.WarpCountry.IP.String()] = probe.WarpCountry.IP
		}
	}
	if len(unique) == 0 {
		return byIP
	}
	sem := make(chan struct{}, p.cfg.IPIntelMaxConcurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range unique {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			intel, ok := p.ipintel.Lookup(ctx, ip)
			if !ok {
				return
			}
			mu.Lock()
			byIP[ip.String()] = &intel
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	if cp := p.startCheckPlaceViaPool(ctx, records, probes); cp != nil {
		var cpMu sync.Mutex
		var cpWg sync.WaitGroup
		cpSem := make(chan struct{}, p.cfg.IPIntelMaxConcurrent)
		for _, ip := range unique {
			cpWg.Add(1)
			go func(ip netip.Addr) {
				defer cpWg.Done()
				select {
				case cpSem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-cpSem }()
				result, ok := cp.Lookup(ctx, ip)
				if !ok {
					return
				}
				cpMu.Lock()
				defer cpMu.Unlock()
				if existing, found := byIP[ip.String()]; found {
					merged := ipintel.MergeResult(*existing, result)
					byIP[ip.String()] = &merged
				} else {
					intel := ipintel.MergeResult(ipintel.Intel{}, result)
					byIP[ip.String()] = &intel
				}
			}(ip)
		}
		cpWg.Wait()
	}
	if pc, cleanup := p.startProxyCheckViaPool(ctx, records, probes); pc != nil {
		defer cleanup()
		var pcMu sync.Mutex
		var pcWg sync.WaitGroup
		pcSem := make(chan struct{}, p.cfg.IPIntelMaxConcurrent)
		for _, ip := range unique {
			pcWg.Add(1)
			go func(ip netip.Addr) {
				defer pcWg.Done()
				select {
				case pcSem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-pcSem }()
				result, ok := pc.Lookup(ctx, ip)
				if !ok {
					return
				}
				pcMu.Lock()
				defer pcMu.Unlock()
				if existing, found := byIP[ip.String()]; found {
					merged := ipintel.MergeResult(*existing, result)
					byIP[ip.String()] = &merged
				} else {
					intel := ipintel.MergeResult(ipintel.Intel{}, result)
					byIP[ip.String()] = &intel
				}
			}(ip)
		}
		pcWg.Wait()
	}
	return byIP
}

// checkDNSBL queries the default DNSBL preset for each unique exit IP. It is
// optional and disabled by default.
func (p *Pipeline) checkDNSBL(ctx context.Context, probes map[int]*exitprobe.ExitProbeResult) map[string][]dnsbl.Result {
	byIP := make(map[string][]dnsbl.Result)
	if !p.cfg.DNSBLEnabled {
		return byIP
	}
	unique := make(map[string]netip.Addr)
	for _, probe := range probes {
		if probe == nil {
			continue
		}
		if probe.DirectCountry.Valid() {
			unique[probe.DirectCountry.IP.String()] = probe.DirectCountry.IP
		}
		if probe.WarpCountry.Valid() {
			unique[probe.WarpCountry.IP.String()] = probe.WarpCountry.IP
		}
	}
	sem := make(chan struct{}, p.cfg.DNSBLMaxConcurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range unique {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			results := dnsbl.CheckIP(ctx, ip, dnsbl.DefaultLists, p.cfg.DNSBLTimeout, p.cfg.DNSBLMaxConcurrent)
			mu.Lock()
			byIP[ip.String()] = results
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return byIP
}
// ServiceCheckResult reports the outcome of a background service-check batch.
type ServiceCheckResult struct {
	Candidates   int
	Checked      int
	CachedHits   int
}

// RunServiceChecks probes service availability for a batch of stale exit IPs.
// It runs in its own ticker, outside the refresh context, and caches results
// by IP so repeat IPs are not re-checked every cycle.
func (p *Pipeline) RunServiceChecks(ctx context.Context) ServiceCheckResult {
	result := ServiceCheckResult{}
	if p.serviceCache == nil {
		return result
	}
	cached, ok := p.Cached()
	if !ok {
		return result
	}
	type ipInfo struct {
		record parse.ProxyRecord
		route  string
	}
	unique := make(map[string]ipInfo)
	for _, entry := range cached.Entries {
		if entry.DirectHealthy {
			if ip := directExitIP(entry.Countries); ip != "" {
				unique[ip] = ipInfo{entry.Entry.Record, "direct"}
			}
		}
		if entry.WarpHealthy {
			if ip := warpExitIP(entry.Countries); ip != "" {
				if _, exists := unique[ip]; !exists {
					unique[ip] = ipInfo{entry.Entry.Record, "warp"}
				}
			}
		}
	}
	ips := make([]string, 0, len(unique))
	for ip := range unique {
		ips = append(ips, ip)
	}
	result.Candidates = len(ips)
	stale := p.serviceCache.StaleIPs(ips)
	result.CachedHits = len(ips) - len(stale)
	if len(stale) > p.cfg.ServiceCheckBatchSize {
		stale = stale[:p.cfg.ServiceCheckBatchSize]
	}
	if len(stale) == 0 {
		return result
	}
	records := make([]parse.ProxyRecord, 0, len(stale))
	ipToIndex := make(map[string]int, len(stale))
	ipToRoute := make(map[string]string, len(stale))
	for _, ip := range stale {
		ipToIndex[ip] = len(records)
		records = append(records, unique[ip].record)
		ipToRoute[ip] = unique[ip].route
	}
	ep := exitprobe.NewExitProber(p.cfg)
	if ep.StartWithProxies(records) != nil {
		return result
	}
	defer ep.Stop()
	checkers := servicecheck.DefaultCheckers()
	timeout := p.cfg.ServiceCheckTimeout
	sem := make(chan struct{}, p.cfg.ServiceCheckMaxConcurrent)
	var wg sync.WaitGroup
	for _, ip := range stale {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			index := ipToIndex[ip]
			var tag string
			if ipToRoute[ip] == "warp" {
				tag = fmt.Sprintf("warp_%d_out", index)
			} else {
				tag = fmt.Sprintf("proxy_%d_out", index)
			}
			results := servicecheck.CheckAll(ctx, ep.HTTPClient(tag, timeout), checkers)
			p.serviceCache.Set(ip, results)
		}(ip)
	}
	wg.Wait()
	result.Checked = len(stale)
	p.refreshServiceMetrics()
	return result
}

func directExitIP(countries country.RouteCountries) string {
	if countries.DirectV4.Available && countries.DirectV4.IP.IsValid() {
		return countries.DirectV4.IP.Unmap().String()
	}
	if countries.DirectV6.Available && countries.DirectV6.IP.IsValid() {
		return countries.DirectV6.IP.Unmap().String()
	}
	return ""
}

func warpExitIP(countries country.RouteCountries) string {
	if countries.WarpV4.Available && countries.WarpV4.IP.IsValid() {
		return countries.WarpV4.IP.Unmap().String()
	}
	if countries.WarpV6.Available && countries.WarpV6.IP.IsValid() {
		return countries.WarpV6.IP.Unmap().String()
	}
	return ""
}

// checkPorts probes a small set of TCP ports on each unique exit IP. It is
// optional and disabled by default; enable only when you accept the extra
// active probing traffic.
func (p *Pipeline) checkPorts(ctx context.Context, probes map[int]*exitprobe.ExitProbeResult) map[string][]portcheck.PortResult {
	byIP := make(map[string][]portcheck.PortResult)
	if !p.cfg.PortCheckEnabled {
		return byIP
	}
	unique := make(map[string]string)
	for _, probe := range probes {
		if probe == nil {
			continue
		}
		if probe.DirectCountry.Valid() {
			unique[probe.DirectCountry.IP.String()] = probe.DirectCountry.IP.String()
		}
		if probe.WarpCountry.Valid() {
			unique[probe.WarpCountry.IP.String()] = probe.WarpCountry.IP.String()
		}
	}
	sem := make(chan struct{}, p.cfg.PortCheckMaxConcurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range unique {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			results := portcheck.CheckPorts(ctx, ip, portcheck.DefaultPorts, p.cfg.PortCheckTimeout, p.cfg.PortCheckMaxConcurrent)
			mu.Lock()
			byIP[ip] = results
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return byIP
}
// startCheckPlaceViaPool builds a CheckPlace provider routed through the first
// healthy proxy in the pool that can reach ipinfo.check.place without a
// Cloudflare block. It returns nil if no proxy works or the feature is off.
func (p *Pipeline) startCheckPlaceViaPool(ctx context.Context, records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult) *ipintel.CheckPlace {
	if !p.cfg.IPIntelCheckPlace {
		return nil
	}
	healthy := make([]parse.ProxyRecord, 0, 8)
	for i, record := range records {
		if probe := probes[i]; probe != nil && probe.Metrics.InternetReachable {
			healthy = append(healthy, record)
			if len(healthy) >= 8 {
				break
			}
		}
	}
	if len(healthy) == 0 {
		return nil
	}
	gateway, err := exitprobe.StartFetchGateway(healthy)
	if err != nil {
		return nil
	}
	for index := range healthy {
		tag := fmt.Sprintf("gateway_%d_out", index)
		transport := &http.Transport{
			DialContext:           gateway.DialContext(tag),
			TLSHandshakeTimeout:   p.cfg.IPIntelTimeout,
			ResponseHeaderTimeout: p.cfg.IPIntelTimeout,
		}
		client := &http.Client{Transport: transport, Timeout: p.cfg.IPIntelTimeout}
		cp := ipintel.NewCheckPlace(client)
		probeCtx, cancel := context.WithTimeout(ctx, p.cfg.IPIntelTimeout)
		_, ok := cp.Lookup(probeCtx, netip.MustParseAddr("8.8.8.8"))
		cancel()
		if ok {
			return cp
		}
	}
	gateway.Close()
	return nil
}

func cloneCachedEntries(entries []CachedEntry) []CachedEntry {
	result := make([]CachedEntry, len(entries))
	for i, entry := range entries {
		result[i] = CachedEntry{
			Entry:         cloneRenamedEntry(entry.Entry),
			WarpEntry:     cloneRenamedEntry(entry.WarpEntry),
			Countries:     entry.Countries,
			DirectHealthy: entry.DirectHealthy,
			WarpHealthy:    entry.WarpHealthy,
			Intel:         cloneIntel(entry.Intel),
			WarpIntel:     cloneIntel(entry.WarpIntel),
			Services:      append([]servicecheck.Result(nil), entry.Services...),
			WarpServices:  append([]servicecheck.Result(nil), entry.WarpServices...),
			PortResults:     append([]portcheck.PortResult(nil), entry.PortResults...),
			WarpPortResults: append([]portcheck.PortResult(nil), entry.WarpPortResults...),
			DNSBLResults:      append([]dnsbl.Result(nil), entry.DNSBLResults...),
			WarpDNSBLResults:  append([]dnsbl.Result(nil), entry.WarpDNSBLResults...),
		}
	}
	return result
}

func selectWarpReprobeCandidates(entries []CachedEntry) []parse.ProxyRecord {
	candidates := make([]parse.ProxyRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.WarpHealthy && country.NeedsWarpReprobe(entry.Countries) {
			candidates = append(candidates, entry.Entry.Record)
		}
	}
	return candidates
}

func cloneRenamedEntry(entry rename.RenamedEntry) rename.RenamedEntry {
	copy := entry
	copy.Record.QueryParams = make(map[string]string, len(entry.Record.QueryParams))
	for key, value := range entry.Record.QueryParams {
		copy.Record.QueryParams[key] = value
	}
	return copy
}

// startProxyCheckViaPool creates a ProxyCheck provider with HTTP clients
// routed through the proxy pool. It returns a cleanup func that closes the
// gateway; callers must defer it. Returns nil if disabled or no healthy proxy.
func (p *Pipeline) startProxyCheckViaPool(ctx context.Context, records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult) (*ipintel.ProxyCheck, func()) {
	if !p.cfg.ProxyCheckEnabled {
		return nil, nil
	}
	healthy := make([]parse.ProxyRecord, 0, 8)
	for i, record := range records {
		if probe := probes[i]; probe != nil && probe.Metrics.InternetReachable {
			healthy = append(healthy, record)
			if len(healthy) >= 8 {
				break
			}
		}
	}
	if len(healthy) == 0 {
		return nil, nil
	}
	gateway, err := exitprobe.StartFetchGateway(healthy)
	if err != nil {
		return nil, nil
	}
	clients := make([]*http.Client, 0, len(healthy))
	for i := range healthy {
		tag := fmt.Sprintf("gateway_%d_out", i)
		transport := &http.Transport{
			DialContext:           gateway.DialContext(tag),
			TLSHandshakeTimeout:   p.cfg.ProxyCheckTimeout,
			ResponseHeaderTimeout: p.cfg.ProxyCheckTimeout,
		}
		clients = append(clients, &http.Client{Transport: transport, Timeout: p.cfg.ProxyCheckTimeout})
	}
	pc := ipintel.NewProxyCheck(clients, p.cfg.ProxyCheckTimeout)
	if pc == nil {
		gateway.Close()
		return nil, nil
	}
	return pc, func() { gateway.Close() }
}
