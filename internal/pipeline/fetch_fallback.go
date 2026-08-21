package pipeline

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/parse"
)

const maxGatewayCandidates = 6

// fetchAllSources fetches every subscription URL: sources with a dedicated
// proxy (SOURCE_FETCH_PROXIES, e.g. an RU socks5 for RU-only hosts) go
// through it first and fall back to direct egress on proxy failure.
func (p *Pipeline) fetchAllSources(ctx context.Context) []fetch.FetchResult {
	urls := p.cfg.SubscriptionURLs
	results := make([]fetch.FetchResult, len(urls))
	directIdx := make([]int, 0, len(urls))

	for i, url := range urls {
		proxyURL := p.cfg.FetchProxyURL(i)
		if proxyURL == "" {
			directIdx = append(directIdx, i)
			continue
		}
		transport, err := fetch.Socks5Transport(proxyURL, 15*time.Second)
		if err != nil {
			log.Printf("[fetch] invalid dedicated proxy for source %d: %v", i, err)
			directIdx = append(directIdx, i)
			continue
		}
		result := fetch.FetchSubscriptionsVia(ctx, []string{url}, 20*time.Second, transport, "socks5")[0]
		if result.Status == "ok" {
			results[i] = result
			continue
		}
		log.Printf("[fetch] dedicated proxy failed for source %d, retrying direct", i)
		directIdx = append(directIdx, i)
	}

	if len(directIdx) > 0 {
		directURLs := make([]string, len(directIdx))
		for j, i := range directIdx {
			directURLs[j] = urls[i]
		}
		for j, result := range fetch.FetchSubscriptions(ctx, directURLs, 15*time.Second) {
			results[directIdx[j]] = result
		}
	}
	return results
}

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
	gateway, err := exitprobe.StartFetchGatewayContext(ctx, candidates)
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
// from the last published cache, one per distinct exit country. Country
// diversity matters: geo-blocked sources (e.g. RU/CIS-only subscriptions)
// refuse some exit countries but accept others, so the retry loop must span
// countries rather than retrying the same region. Direct health is the right
// signal here: the gateway dials the proxy server from our own egress.
func (p *Pipeline) gatewayCandidates(limit int) []parse.ProxyRecord {
	data, ok := p.Cached()
	if !ok {
		return nil
	}
	seenIdentity := map[string]bool{}
	seenCountry := map[string]bool{}
	records := make([]parse.ProxyRecord, 0, limit)
	for _, entry := range data.Entries {
		if !entry.DirectHealthy {
			continue
		}
		countryCode := directExitCountry(entry.Countries)
		if seenCountry[countryCode] {
			continue
		}
		record := entry.Entry.Record
		key := identity(record)
		if seenIdentity[key] {
			continue
		}
		seenIdentity[key] = true
		seenCountry[countryCode] = true
		records = append(records, record)
		if len(records) >= limit {
			break
		}
	}
	return records
}

func directExitCountry(countries country.RouteCountries) string {
	for _, candidate := range []string{
		countries.DirectV4.ObservedCountry,
		countries.DirectV4.Country,
		countries.DirectV6.ObservedCountry,
		countries.DirectV6.Country,
	} {
		if candidate != "" {
			return candidate
		}
	}
	return "unknown"
}
