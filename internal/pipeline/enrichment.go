package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/dnsbl"
	"github.com/michael/vless-sub-server/internal/enrichment"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/ipintel"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/portcheck"
)

func (p *Pipeline) cachedEnrichmentByIP(probes map[int]*exitprobe.ExitProbeResult) (map[string]*ipintel.Intel, map[string][]portcheck.PortResult, map[string][]dnsbl.Result) {
	intelByIP := make(map[string]*ipintel.Intel)
	portsByIP := make(map[string][]portcheck.PortResult)
	dnsblByIP := make(map[string][]dnsbl.Result)
	for _, probe := range probes {
		if probe == nil {
			continue
		}
		for _, observation := range []netip.Addr{probe.DirectCountry.IP, probe.WarpCountry.IP} {
			if !observation.IsValid() {
				continue
			}
			ip := observation.Unmap().String()
			if intel := p.cachedIntel(ip); intel != nil {
				intelByIP[ip] = intel
			}
			if ports := p.cachedPorts(ip); len(ports) > 0 {
				portsByIP[ip] = ports
			}
			if results := p.cachedDNSBL(ip); len(results) > 0 {
				dnsblByIP[ip] = results
			}
		}
	}
	return intelByIP, portsByIP, dnsblByIP
}

type EnrichmentCheckResult struct {
	Candidates int
	Checked    int
	CachedHits int
}

type enrichmentNeeds struct {
	intel bool
	ports bool
	dnsbl bool
}

// RunEnrichmentChecks updates reputation, port, and DNSBL caches outside the
// subscription refresh deadline. Each exit IP is processed at most once per batch.
func (p *Pipeline) RunEnrichmentChecks(ctx context.Context) EnrichmentCheckResult {
	result := EnrichmentCheckResult{}
	cached, ok := p.Cached()
	if !ok {
		return result
	}
	ips := uniqueHealthyExitIPs(cached.Entries)
	result.Candidates = len(ips)
	if len(ips) == 0 {
		return result
	}

	needs := make(map[string]enrichmentNeeds, len(ips))
	ordered := make([]string, 0, len(ips))
	add := func(keys []string, apply func(*enrichmentNeeds)) {
		for _, ip := range keys {
			value, exists := needs[ip]
			if !exists {
				ordered = append(ordered, ip)
			}
			apply(&value)
			needs[ip] = value
		}
	}
	if p.cfg.IPIntelEnabled && p.intelCache != nil && p.intelLookup != nil {
		add(p.intelCache.StaleKeys(ips), func(value *enrichmentNeeds) { value.intel = true })
	}
	if p.cfg.PortCheckEnabled && p.portCache != nil && p.portLookup != nil {
		add(p.portCache.StaleKeys(ips), func(value *enrichmentNeeds) { value.ports = true })
	}
	if p.cfg.DNSBLEnabled && p.dnsblCache != nil && p.dnsblLookup != nil {
		add(p.dnsblCache.StaleKeys(ips), func(value *enrichmentNeeds) { value.dnsbl = true })
	}
	result.CachedHits = len(ips) - len(ordered)
	if len(ordered) > p.cfg.EnrichmentCheckBatchSize {
		ordered = ordered[:p.cfg.EnrichmentCheckBatchSize]
	}
	if len(ordered) == 0 {
		p.refreshEnrichmentMetrics()
		return result
	}
	proxyCheck, checkPlaces, cleanup := p.startIntelPool(ctx, cached.Entries, needs, ordered)
	if cleanup != nil {
		defer cleanup()
	}

	maxConcurrent := p.cfg.EnrichmentCheckMaxConcurrent
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, ipString := range ordered {
		wg.Add(1)
		go func(ipString string, todo enrichmentNeeds) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			ip, err := netip.ParseAddr(ipString)
			if err != nil {
				return
			}
			if todo.intel {
				intel, ok := p.intelLookup(ctx, ip)
				for _, provider := range checkPlaces {
					value, success := provider.Lookup(ctx, ip)
					outcome := ipintel.ProviderTransport
					if success {
						outcome = ipintel.ProviderSuccess
						intel = ipintel.MergeResult(intel, value)
						ok = true
					}
					if p.ipintel != nil {
						p.ipintel.RecordProvider(provider.Name(), outcome)
					}
					if success {
						break
					}
				}
				if proxyCheck != nil {
					if value, outcome := proxyCheck.LookupDetailed(ctx, ip); outcome == ipintel.ProviderSuccess {
						intel = ipintel.MergeResult(intel, value)
						ok = true
					}
				}
				if ok && ctx.Err() == nil {
					p.intelCache.Set(ipString, intel)
				}
			}
			if todo.ports {
				ports := p.portLookup(ctx, ipString)
				if ctx.Err() == nil {
					p.portCache.Set(ipString, ports)
				}
			}
			if todo.dnsbl {
				results := p.dnsblLookup(ctx, ip)
				if ctx.Err() == nil {
					p.dnsblCache.Set(ipString, results)
				}
			}
		}(ipString, needs[ipString])
	}
	wg.Wait()
	if cleanup != nil {
		cleanup()
		cleanup = nil
	}
	result.Checked = len(ordered)
	if ctx.Err() == nil {
		p.markChecksCompleted(needs, ordered, time.Now())
	}
	p.refreshCachedEnrichment()
	return result
}

func (p *Pipeline) startIntelPool(ctx context.Context, entries []CachedEntry, needs map[string]enrichmentNeeds, ordered []string) (*ipintel.ProxyCheck, []*ipintel.CheckPlace, func()) {
	if !p.cfg.ProxyCheckEnabled && !p.cfg.IPIntelCheckPlace {
		return nil, nil, nil
	}
	hasIntel := false
	for _, ip := range ordered {
		hasIntel = hasIntel || needs[ip].intel
	}
	if !hasIntel {
		return nil, nil, nil
	}
	records := healthyPoolRecords(entries, 8)
	if len(records) == 0 {
		return nil, nil, nil
	}
	gateway, err := exitprobe.StartFetchGatewayContext(ctx, records)
	if err != nil {
		return nil, nil, nil
	}
	clients := distinctGatewayClients(ctx, gateway, len(records), p.cfg.ProxyCheckTimeout)
	if len(clients) == 0 {
		gateway.Close()
		return nil, nil, nil
	}
	var proxyCheck *ipintel.ProxyCheck
	if p.cfg.ProxyCheckEnabled {
		proxyCheck = ipintel.NewProxyCheck(clients, p.cfg.ProxyCheckTimeout)
		proxyCheck.SetRecorder(func(outcome ipintel.ProviderOutcome) {
			if p.ipintel != nil {
				p.ipintel.RecordProvider("proxycheck.io", outcome)
			}
		})
	}
	checkPlaces := make([]*ipintel.CheckPlace, 0, len(clients))
	if p.cfg.IPIntelCheckPlace {
		for _, client := range clients {
			checkPlaces = append(checkPlaces, ipintel.NewCheckPlace(client))
		}
	}
	return proxyCheck, checkPlaces, gateway.Close
}

func healthyPoolRecords(entries []CachedEntry, limit int) []parse.ProxyRecord {
	seen := map[string]struct{}{}
	records := make([]parse.ProxyRecord, 0, limit)
	for _, entry := range entries {
		if !entry.DirectHealthy && !entry.WarpHealthy {
			continue
		}
		record := entry.Entry.Record
		key := identity(record)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, record)
		if len(records) >= limit {
			break
		}
	}
	return records
}

func distinctGatewayClients(ctx context.Context, gateway *exitprobe.FetchGateway, count int, timeout time.Duration) []*http.Client {
	clients := make([]*http.Client, 0, count)
	seenExits := map[string]struct{}{}
	for index := 0; index < count; index++ {
		transport := &http.Transport{
			DialContext:           gateway.DialContext(fmt.Sprintf("gateway_%d_out", index)),
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
		client := &http.Client{Transport: transport, Timeout: timeout}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://speed.cloudflare.com/cdn-cgi/trace", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		exitIP := traceValue(string(body), "ip")
		if _, err := netip.ParseAddr(exitIP); err != nil {
			continue
		}
		if _, ok := seenExits[exitIP]; ok {
			continue
		}
		seenExits[exitIP] = struct{}{}
		clients = append(clients, client)
	}
	return clients
}

func traceValue(body, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func uniqueHealthyExitIPs(entries []CachedEntry) []string {
	seen := make(map[string]struct{}, len(entries)*2)
	result := make([]string, 0, len(entries)*2)
	add := func(ip string) {
		if ip == "" {
			return
		}
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		result = append(result, ip)
	}
	for _, entry := range entries {
		if entry.DirectHealthy {
			add(directExitIP(entry.Countries))
		}
		if entry.WarpHealthy {
			add(warpExitIP(entry.Countries))
		}
	}
	return result
}

func (p *Pipeline) refreshCachedEnrichment() {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	cached, ok := p.Cached()
	if !ok {
		return
	}
	for i := range cached.Entries {
		entry := &cached.Entries[i]
		entry.Intel = p.cachedIntel(directExitIP(entry.Countries))
		entry.WarpIntel = p.cachedIntel(warpExitIP(entry.Countries))
		entry.PortResults = p.cachedPorts(directExitIP(entry.Countries))
		entry.WarpPortResults = p.cachedPorts(warpExitIP(entry.Countries))
		entry.DNSBLResults = p.cachedDNSBL(directExitIP(entry.Countries))
		entry.WarpDNSBLResults = p.cachedDNSBL(warpExitIP(entry.Countries))
	}
	p.cache.Store(cached)
	p.refreshEnrichmentMetrics()
}

func (p *Pipeline) cachedIntel(ip string) *ipintel.Intel {
	intel, state := p.intelCache.Get(ip)
	if state == enrichment.Missing {
		return nil
	}
	copy := intel
	copy.Sources = append([]string(nil), intel.Sources...)
	return &copy
}

func (p *Pipeline) cachedPorts(ip string) []portcheck.PortResult {
	results, state := p.portCache.Get(ip)
	if state == enrichment.Missing {
		return nil
	}
	return append([]portcheck.PortResult(nil), results...)
}

func (p *Pipeline) cachedDNSBL(ip string) []dnsbl.Result {
	results, state := p.dnsblCache.Get(ip)
	if state == enrichment.Missing {
		return nil
	}
	return append([]dnsbl.Result(nil), results...)
}

func (p *Pipeline) markChecksCompleted(needs map[string]enrichmentNeeds, checked []string, at time.Time) {
	completed := map[string]bool{}
	for _, ip := range checked {
		todo := needs[ip]
		completed["ipintel"] = completed["ipintel"] || todo.intel
		completed["port"] = completed["port"] || todo.ports
		completed["dnsbl"] = completed["dnsbl"] || todo.dnsbl
	}
	p.checkMu.Lock()
	if p.checkRuns == nil {
		p.checkRuns = make(map[string]time.Time)
	}
	for checker, ok := range completed {
		if ok {
			p.checkRuns[checker] = at
		}
	}
	p.checkMu.Unlock()
}
