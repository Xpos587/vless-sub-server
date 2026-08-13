// Package pipeline composes fetching, probing, quality state, and publication.
package pipeline

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/quality"
	"github.com/michael/vless-sub-server/internal/rename"
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
	Countries     country.RouteCountries
	DirectHealthy bool
	WarpHealthy   bool
}

type outputEntry struct {
	Record    parse.ProxyRecord
	Geo       *geo.GeoInfo
	IsLAN     bool
	Countries country.RouteCountries
}

type RefreshResult struct {
	Published                                bool
	Parsed, Resolved                         int
	Good, Partial, Dead                      int
	BandwidthCandidates, BandwidthSuccesses  int
	CountryStateSaveFailed                   bool
	DirectCountrySources, WarpCountrySources map[string]int
}

type Pipeline struct {
	cfg          *config.Config
	dnsCache     *dns.DNSCache
	sourceCache  *fetch.SourceCache
	runtime      *quality.Store
	countryState *country.StateStore
	cache        atomic.Value // stores *CachedData
}

const bandwidthStageTimeout = 30 * time.Second

func New(cfg *config.Config, dnsCache *dns.DNSCache) *Pipeline {
	state, _ := country.OpenStateStore("")
	return &Pipeline{cfg: cfg, dnsCache: dnsCache, sourceCache: fetch.NewSourceCache(), runtime: quality.NewStore(), countryState: state}
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
	now := time.Now()
	result := RefreshResult{DirectCountrySources: make(map[string]int), WarpCountrySources: make(map[string]int)}
	fetched := fetch.FetchSubscriptions(ctx, p.cfg.SubscriptionURLs, 15*time.Second)
	lines := p.sourceCache.Merge(now, fetched, p.cfg.SourceStaleMaxAge)
	parsed := parse.ParseAllLines(lines)
	filtered := parse.ApplyNameFilter(parsed.Records, p.cfg.NameInclude, p.cfg.NameExclude)
	result.Parsed = len(filtered)

	dnsMap := dns.ResolveHosts(ctx, dedupHosts(filtered), 20, p.cfg.DNSTimeout, p.dnsCache)
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

	entries, geoAvailable := p.outputEntries(probed, probes, dnsMap, &result)
	hasExisting := p.cache.Load() != nil
	if !CanPublish(len(entries), hasExisting) {
		return result
	}
	renameInput := make([]struct {
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
	}
	renamed := rename.RenameAll(renameInput)
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
		cachedEntries[i] = CachedEntry{Entry: cloneRenamedEntry(entry), Countries: entries[i].Countries, DirectHealthy: runtime.DirectHealthy, WarpHealthy: runtime.WarpHealthy}
		if runtime.DirectHealthy {
			directEntries = append(directEntries, entry)
		}
		if runtime.WarpHealthy {
			warpEntries = append(warpEntries, entry)
		}
	}
	p.cache.Store(&CachedData{Entries: cachedEntries, Metadata: meta, Output: format.FormatOutput(directEntries, meta), JSONOutput: format.FormatXrayJSON(warpEntries, meta), LastRefresh: now})
	if p.countryState != nil {
		if err := p.countryState.Save(); err != nil {
			result.CountryStateSaveFailed = true
		}
	}
	result.Published = true
	p.dnsCache.Purge()
	return result
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

func (p *Pipeline) outputEntries(records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult, dnsMap map[string]*dns.DNSResult, result *RefreshResult) ([]outputEntry, int) {
	type item struct {
		record  parse.ProxyRecord
		runtime quality.Runtime
		geo     *geo.GeoInfo
		lan     bool
	}
	items := make([]item, 0, len(records))
	geoAvailable := 0
	for _, record := range records {
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
		if info != nil {
			geoAvailable++
		}
		items = append(items, item{record, runtime, info, dnsMap[record.Host].IsPrivate})
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
		entries = append(entries, outputEntry{Record: item.record, Geo: item.geo, IsLAN: item.lan, Countries: item.runtime.Countries})
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
func cloneGeo(info *geo.GeoInfo) *geo.GeoInfo {
	if info == nil {
		return nil
	}
	copy := *info
	return &copy
}

func cloneCachedEntries(entries []CachedEntry) []CachedEntry {
	result := make([]CachedEntry, len(entries))
	for i, entry := range entries {
		result[i] = CachedEntry{Entry: cloneRenamedEntry(entry.Entry), Countries: entry.Countries}
	}
	return result
}

func cloneRenamedEntry(entry rename.RenamedEntry) rename.RenamedEntry {
	copy := entry
	copy.Record.QueryParams = make(map[string]string, len(entry.Record.QueryParams))
	for key, value := range entry.Record.QueryParams {
		copy.Record.QueryParams[key] = value
	}
	return copy
}
