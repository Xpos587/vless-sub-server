// Package pipeline composes fetching, probing, quality state, and publication.
package pipeline

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
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
	LastRefresh time.Time
}

type RefreshResult struct {
	Published                               bool
	Parsed, Resolved                        int
	Good, Partial, Dead                     int
	BandwidthCandidates, BandwidthSuccesses int
}

type Pipeline struct {
	cfg         *config.Config
	dnsCache    *dns.DNSCache
	sourceCache *fetch.SourceCache
	runtime     *quality.Store
	cache       atomic.Value // stores *CachedData
}

const bandwidthStageTimeout = 30 * time.Second

func New(cfg *config.Config, dnsCache *dns.DNSCache) *Pipeline {
	return &Pipeline{cfg: cfg, dnsCache: dnsCache, sourceCache: fetch.NewSourceCache(), runtime: quality.NewStore()}
}

func (p *Pipeline) Cached() (*CachedData, bool) {
	v := p.cache.Load()
	if v == nil {
		return nil, false
	}
	data := *(v.(*CachedData))
	data.JSONOutput = append([]byte(nil), data.JSONOutput...)
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
	result := RefreshResult{}
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
	renamed := rename.RenameAll(entries)
	sourcesOK := 0
	for _, source := range fetched {
		if source.Status == "ok" {
			sourcesOK++
		}
	}
	meta := format.FormatMetadata{TotalFetched: len(lines), TotalParsed: len(filtered), TotalSkipped: parsed.Skipped, TotalDuplicates: parsed.Duplicates, TotalAlive: len(renamed), TotalDead: result.Dead, SourcesOK: sourcesOK, SourcesFailed: len(fetched) - sourcesOK, GeoAvailable: geoAvailable, GeoTotal: len(probed)}
	p.cache.Store(&CachedData{Output: format.FormatOutput(renamed, meta), JSONOutput: format.FormatXrayJSON(renamed, meta), LastRefresh: now})
	result.Published = true
	p.dnsCache.Purge()
	return result
}

func (p *Pipeline) updateRuntime(key string, probe *exitprobe.ExitProbeResult, now time.Time) {
	previous, exists := p.runtime.Get(key)
	metrics := quality.Metrics{}
	if probe != nil {
		metrics = probe.Metrics
	}
	observation := quality.Blackhole
	if metrics.SuccessCount*5 >= metrics.SampleCount*4 && metrics.SampleCount > 0 {
		observation = quality.Good
	} else if metrics.InternetReachable {
		observation = quality.Partial
	}
	state := previous.StateData
	if !exists {
		state.State = quality.Healthy
	}
	state = quality.Transition(state, observation, now, quality.DefaultStateConfig())
	runtime := previous
	runtime.Key, runtime.State, runtime.StateData, runtime.Reachable = key, state.State, state, metrics.InternetReachable
	if metrics.InternetReachable {
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
	p.runtime.Set(runtime)
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

func (p *Pipeline) outputEntries(records []parse.ProxyRecord, probes map[int]*exitprobe.ExitProbeResult, dnsMap map[string]*dns.DNSResult, result *RefreshResult) ([]struct {
	Record parse.ProxyRecord
	Geo    *geo.GeoInfo
	IsLAN  bool
}, int) {
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
	entries := make([]struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}, 0, len(items))
	for _, item := range items {
		entries = append(entries, struct {
			Record parse.ProxyRecord
			Geo    *geo.GeoInfo
			IsLAN  bool
		}{item.record, item.geo, item.lan})
	}
	return entries, geoAvailable
}

func hasReachabilityWitness(probes map[int]*exitprobe.ExitProbeResult) bool {
	for _, probe := range probes {
		if probe != nil && probe.Metrics.InternetReachable {
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
