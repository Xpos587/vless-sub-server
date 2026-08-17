package pipeline

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/parse"
)

const maxGatewayCandidates = 3

// retryFailedFetchesViaPool refetches sources that failed on direct egress
// through healthy proxies from the pool itself. An anti-censorship aggregator
// should be able to use its own verified exits: subscription hosts are
// regularly geo-blocked (oversub serves only RU) or RKN-blocked from the
// server location.
func (p *Pipeline) retryFailedFetchesViaPool(ctx context.Context, fetched []fetch.FetchResult) []fetch.FetchResult {
	if !p.cfg.FetchProxyFallback {
		return fetched
	}
	failed := make([]int, 0, len(fetched))
	for i, result := range fetched {
		if result.Status != "ok" {
			failed = append(failed, i)
		}
	}
	if len(failed) == 0 {
		return fetched
	}

	candidates := p.gatewayCandidates(maxGatewayCandidates)
	if len(candidates) == 0 {
		return fetched
	}
	gateway, err := exitprobe.StartFetchGateway(candidates)
	if err != nil {
		log.Printf("[fetch] gateway start failed: %v", err)
		return fetched
	}
	defer gateway.Close()

	for _, idx := range failed {
		url := fetched[idx].URL
		for _, tag := range gateway.Tags() {
			transport := &http.Transport{
				DialContext:           gateway.DialContext(tag),
				ForceAttemptHTTP2:     true,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
			}
			result := fetch.FetchSubscriptionsVia(ctx, []string{url}, 20*time.Second, transport, "proxy")[0]
			if result.Status == "ok" {
				log.Printf("[fetch] recovered source via pool gateway (%d lines)", len(result.Lines))
				fetched[idx] = result
				break
			}
		}
	}
	return fetched
}

// gatewayCandidates picks up to limit distinct direct-healthy pool records
// from the last published cache. Direct health is the right signal here: the
// gateway dials the proxy server from our own egress.
func (p *Pipeline) gatewayCandidates(limit int) []parse.ProxyRecord {
	data, ok := p.Cached()
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	records := make([]parse.ProxyRecord, 0, limit)
	for _, entry := range data.Entries {
		if !entry.DirectHealthy {
			continue
		}
		record := entry.Entry.Record
		key := identity(record)
		if seen[key] {
			continue
		}
		seen[key] = true
		records = append(records, record)
		if len(records) >= limit {
			break
		}
	}
	return records
}
