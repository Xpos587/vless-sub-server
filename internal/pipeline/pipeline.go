package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/probe"
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
func ProbeAndFilter(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration) ProbeAndFilterResult {
	uniqueHosts := dedupHosts(records)
	dnsMap := dns.ResolveHosts(ctx, uniqueHosts, maxConcurrent, dnsTimeout)

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