package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/probe"
	"golang.org/x/sync/errgroup"
)

// ResolvedProxy holds a proxy record with its DNS resolution result.
type ResolvedProxy struct {
	Record parse.ProxyRecord
	DNS    *dns.DNSResult
	IsLAN  bool
}

// ProbedProxy holds a proxy record with both DNS and TCP probe results.
type ProbedProxy struct {
	Record parse.ProxyRecord
	DNS    *dns.DNSResult
	Probe  *probe.ProbeResult
	IsLAN  bool
}

// ProbeAndFilterResult is the return type for ProbeAndFilter.
type ProbeAndFilterResult struct {
	Alive       []ProbedProxy
	DNSResolved int // total records that had DNS results (alive + TCP-dead)
}

// ProbeAndFilter resolves DNS for all records, TCP-probes the ones that
// resolved, and returns only the alive proxies along with the total
// count of records that had DNS results.
func ProbeAndFilter(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration, cache *dns.DNSCache) ProbeAndFilterResult {
	uniqueHosts := dedupHosts(records)
	dnsMap := dns.ResolveHosts(ctx, uniqueHosts, maxConcurrent, dnsTimeout, cache)

	var withDNS []ResolvedProxy
	for _, r := range records {
		if d, ok := dnsMap[r.Host]; ok && d.IP != "" {
			withDNS = append(withDNS, ResolvedProxy{
				Record: r,
				DNS:    d,
				IsLAN:  d.IsPrivate,
			})
		}
	}

	hosts := make([]probe.HostSpec, len(withDNS))
	for i, r := range withDNS {
		hosts[i] = probe.HostSpec{
			Host: r.Record.Host,
			IP:   r.DNS.IP,
			Port: r.Record.Port,
		}
	}
	probeResults := probe.TCPProbeAll(ctx, hosts, maxConcurrent, tcpTimeout)

	var alive []ProbedProxy
	for _, r := range withDNS {
		key := fmt.Sprintf("%s:%d", r.Record.Host, r.Record.Port)
		if p, ok := probeResults[key]; ok && p.Reachable {
			alive = append(alive, ProbedProxy{
				Record: r.Record,
				DNS:    r.DNS,
				Probe:  p,
				IsLAN:  r.IsLAN,
			})
		}
	}
	return ProbeAndFilterResult{
		Alive:       alive,
		DNSResolved: len(withDNS),
	}
}

// ProbeAndFilterStream resolves DNS and TCP-probes with streaming overlap:
// TCP probing begins as soon as the first DNS result arrives, rather than
// waiting for all DNS resolutions to complete.
func ProbeAndFilterStream(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration, cache *dns.DNSCache) ProbeAndFilterResult {
	uniqueHosts := dedupHosts(records)

	// Build host -> records index for fast lookup
	hostToRecords := make(map[string][]parse.ProxyRecord)
	for _, r := range records {
		hostToRecords[r.Host] = append(hostToRecords[r.Host], r)
	}

	// Stage 1: Stream DNS results as they arrive
	dnsCh := dns.ResolveStream(ctx, uniqueHosts, maxConcurrent, dnsTimeout, cache)

	// Stage 2: TCP probe each DNS result as it arrives (overlapping)
	type probedResult struct {
		Record parse.ProxyRecord
		DNS    *dns.DNSResult
		Probe  *probe.ProbeResult
		IsLAN  bool
	}
	probedCh := make(chan probedResult, maxConcurrent)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrent)
	dnsResolved := 0
	var mu sync.Mutex

	go func() {
		defer close(probedCh)
		for dnsRes := range dnsCh {
			if dnsRes.IP == "" {
				continue
			}
			mu.Lock()
			dnsResolved++
			mu.Unlock()
			for _, rec := range hostToRecords[dnsRes.Host] {
				rec := rec
				dnsRes := dnsRes
				g.Go(func() error {
					probeRes := probe.TCPProbeSingle(ctx, dnsRes.IP, rec.Port, tcpTimeout)
					if probeRes.Reachable {
						select {
						case probedCh <- probedResult{
							Record: rec,
							DNS:    &dns.DNSResult{Host: dnsRes.Host, IP: dnsRes.IP, IsPrivate: dnsRes.IsPrivate},
							Probe:  probeRes,
							IsLAN:  dnsRes.IsPrivate,
						}:
						case <-ctx.Done():
						}
					}
					return nil
				})
			}
		}
		g.Wait()
	}()

	// Collect results
	var alive []ProbedProxy
	for res := range probedCh {
		alive = append(alive, ProbedProxy{
			Record: res.Record,
			DNS:    res.DNS,
			Probe:  res.Probe,
			IsLAN:  res.IsLAN,
		})
	}

	mu.Lock()
	resolved := dnsResolved
	mu.Unlock()

	return ProbeAndFilterResult{
		Alive:       alive,
		DNSResolved: resolved,
	}
}

func dedupHosts(records []parse.ProxyRecord) []string {
	seen := make(map[string]bool, len(records))
	var hosts []string
	for _, r := range records {
		if !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}