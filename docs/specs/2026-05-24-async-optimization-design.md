# vless-sub-server: Async/Parallel Optimization Design

## Problem

Current pipeline is fully sequential: each phase waits for the previous to complete before starting. With 50 proxies, total refresh takes ~20-33s. Exit-IP probing dominates at 60-80% of wall time.

```
fetch(2s) -> parse(0.1s) -> DNS(5s) -> TCP(3s) -> xray start(3s) -> exit probe(30s) -> geo(1s) -> rename(0.1s)
Total: ~44s worst case
```

## Research Findings

### Agent 1: Pipeline Parallelism
- DNS + TCP can be **fused** — TCP starts as soon as each host resolves (eliminates barrier)
- xray startup can **overlap** with DNS+TCP (pre-warm with all proxies, skip dead ones later)
- Exit-IP probing can be **sharded** across multiple xray instances
- Streaming pipeline: alive records flow into xray shards as they arrive
- **Theoretical speedup: 2-5x**

### Agent 2: xray-core Dynamic API
- xray-core has **first-class dynamic handler API**: `core.AddOutboundHandler()`, `core.AddInboundHandler()`
- `outbound.Manager.RemoveHandler(ctx, tag)` and `inbound.Manager.RemoveHandler(ctx, tag)` work on running instances
- **Long-lived instance pattern**: create instance once, add/remove handlers per refresh cycle — eliminates `New()+Start()+Close()` overhead every 30 min
- Multiple parallel instances viable (2-5 shards recommended)
- Caveat: `outbound.Manager.RemoveHandler` does NOT close the handler (bug in xray-core), must close manually

### Agent 3: Go Async Patterns
- `errgroup.SetLimit(N)` replaces all manual WaitGroup+semaphore patterns with built-in cancellation
- **Streaming pipeline with channels** is highest-impact pattern — overlapping stages
- `singleflight.Group` for DNS dedup (within and across refresh cycles)
- `singleflight.Group` for refresh itself — replaces racy `refreshing` bool
- **Context propagation** is prerequisite — current code uses `context.Background()` internally, breaking cancellation chain
- vegeta's approach: shared `http.Transport` with `MaxConnsPerHost`, DNS cache with TTL
- `sync.Pool` for buffer reuse under high concurrency

### Agent 4: Existing Tools
- **beck-8/subs-check** (Go, 439 commits): most similar project, does subscription checking+conversion+rename
- **Danialsamadi/v2go** (Go): processes 20K configs in 11s, uses **embedded mmdb** for geo lookup instead of API calls
- **xray-checker** (Go): uses xray-core as subprocess (not library), parallel probing with goroutines
- No other project uses xray-core as Go library — vless-sub-server is unique here
- Rust proxy scraper-checker: 2000 concurrent connections by default
- **Key insight**: embedded mmdb for geo lookup eliminates external API rate limits (100x faster)

### Agent 5: Bottleneck Analysis
- Exit-IP probe: **60-80% of total time** (10 concurrent x 5 rounds x 12s timeout)
- MaxConcurrent=10 is too conservative — xray handles parallel SOCKS5 connections fine
- New `http.Client` per probe — no transport reuse, no TLS session caching
- DNS results discarded every 30 min — no cross-cycle caching
- Fixed 500ms retry in DNS — no exponential backoff
- `refreshing` bool has race condition

## Proposed Optimizations (Priority Order)

### P0: Raise exit-probe concurrency (effort: LOW, impact: HIGH)

Change `MAX_CONCURRENT` default from 10 to `min(len(aliveRecords), 50)`.

Current: 50 proxies / 10 concurrent = 5 rounds x 12s = 60s worst case.
After: 50 proxies / 50 concurrent = 1 round x 12s = 12s worst case.

**Savings: 30-60s -> 12s for exit-probe phase.**

Each proxy routes through a different exit IP, so ipwho.is rate limiting is not a concern (requests arrive from different IPs). xray-core handles parallel SOCKS5 connections fine — each inbound/outbound pair is independent.

Files: `internal/config/config.go:14`, `cmd/vless-sub-server/main.go:102`

### P1: Context propagation (effort: LOW, impact: MEDIUM — prerequisite for all other changes)

Thread `context.Context` through all functions. Replace `context.Background()` with derived contexts from the 2-minute pipeline timeout.

Current issues:
- `dns.resolveOne()` creates its own `context.WithTimeout(context.Background(), ...)` — parent cannot cancel
- `fetch.fetchSingle()` has no context at all — `http.NewRequest` not `NewRequestWithContext`
- Cancellation from `refreshSubscriptions` does not propagate to individual operations

After: every function accepts `ctx context.Context` as first param. Pipeline timeout properly cancels all in-flight work.

Files: `internal/fetch/fetch.go`, `internal/dns/dns.go`, `internal/probe/probe.go`, `internal/exitprobe/exitprobe.go`

### P2: Streaming DNS+TCP pipeline (effort: MEDIUM, impact: HIGH)

Fuse DNS resolution and TCP probing into a single streaming stage. TCP probe for host X starts immediately after DNS for host X resolves — no barrier between phases.

```
Current: DNS(5s all) -> TCP(3s all) = 8s
After:   DNS+TCP overlapped = max(5s, 3s) = 5s
```

Implementation: channel-based pipeline. DNS stage sends results downstream as they complete. TCP stage reads from channel, probes concurrently.

Add `singleflight.Group` for DNS dedup — prevents resolving same host twice when multiple proxies share it.

Files: `cmd/vless-sub-server/main.go` (pipeline orchestration), `internal/dns/dns.go` (streaming API), `internal/probe/probe.go` (streaming API)

### P3: Shared http.Transport + connection reuse (effort: LOW, impact: MEDIUM)

Create a single `http.Transport` per `ExitProber` and reuse across probes. Enable TLS session resumption for fallback calls to cloudflare/ipwho.is.

Also: **always drain `resp.Body`** with `io.Copy(io.Discard, resp.Body)` before close — otherwise connections are NOT reused and port exhaustion occurs under load.

For fetch: share a single `http.Client` across all subscription URL fetches.

Files: `internal/exitprobe/exitprobe.go:117-126`, `internal/fetch/fetch.go:44-45`

### P4: Long-lived xray instance with dynamic handlers (effort: MEDIUM-HIGH, impact: HIGH)

Replace current "create instance -> probe -> destroy" pattern with "keep instance alive, add/remove handlers dynamically".

```go
// Lifecycle:
// 1. Create instance once at server startup with infrastructure features + "direct" outbound
// 2. Per refresh: AddInboundHandler + AddOutboundHandler for each alive proxy
// 3. Probe all proxies
// 4. RemoveInboundHandler + RemoveOutboundHandler for all proxies
// 5. Instance stays running until process exits
```

Benefits:
- Eliminates `core.New() + Start()` cost every 30 min (1-5s)
- Infrastructure (DNS, routing, policy) stays warm
- Only proxy-specific handlers are added/removed

Challenge: `RemoveHandler` on outbound manager does NOT close the handler (xray-core bug). Must track and close handlers manually.

Alternative: **Sharded xray instances** (2-5 instances, each with N/K proxies). Simpler to implement, provides parallel startup + parallel probing. No need for dynamic handler API.

Files: `internal/exitprobe/exitprobe.go` (major refactor)

### P5: errgroup unification (effort: LOW, impact: LOW-MEDIUM)

Replace all `sync.WaitGroup` + buffered channel semaphore patterns with `errgroup.Group` + `SetLimit()`. Benefits:
- Built-in context cancellation on first error
- Cleaner code (one `g.Go()` instead of `wg.Add/go/wg.Wait`)
- Unified pattern across all phases

Also: replace racy `refreshing` bool with `singleflight.Group` for the refresh function itself.

Files: `internal/fetch/fetch.go`, `internal/dns/dns.go`, `internal/probe/probe.go`, `internal/exitprobe/exitprobe.go`, `cmd/vless-sub-server/main.go`

### P6: DNS cache across refresh cycles (effort: LOW-MEDIUM, impact: MEDIUM)

Add TTL-aware DNS cache. Proxy server IPs rarely change within 30 minutes. With 10-minute TTL, ~2/3 of hosts hit cache on each refresh.

```go
type DNSCache struct {
    mu      sync.RWMutex
    entries map[string]cacheEntry // host -> {ip, isPrivate, expiresAt}
}
```

Files: `internal/dns/dns.go`

### P7: Embedded mmdb for geo lookup (effort: MEDIUM, impact: HIGH for large proxy lists)

Replace external API calls (ipwho.is, ip-api.com) with local GeoLite2-Country.mmdb + GeoLite2-ASN.mmdb lookups.

Benefits:
- 100x faster (local file lookup vs HTTP round-trip)
- No rate limits (ip-api.com free tier: 45 req/min)
- No dependency on external services
- Works offline

v2go project uses this approach successfully for 20K+ configs.

Trade-off: binary size increases by ~60MB for mmdb files, or require them at runtime.

Files: `internal/geo/geo.go`, `internal/exitprobe/exitprobe.go` (batchGeoLookup removal)

### P8: Incremental refresh (effort: HIGH, impact: HIGH for stable subscriptions)

Cache previous cycle results keyed by `(host, port, UUID)`. On refresh:
1. Diff new subscription against previous cycle
2. Skip exit-IP probing for unchanged proxies (reuse cached exit-IP + geo)
3. Only probe new proxies through xray
4. Re-probe unchanged proxies every N cycles (staleness threshold)

For 50 proxies where 40 are unchanged: probe only 10 new ones. Reduces exit-probe from 30-60s to 12s.

Files: `cmd/vless-sub-server/main.go` (persistent state between refreshes)

## Estimated Impact Summary

| Priority | Optimization | Effort | Current | After | Savings |
|----------|-------------|--------|---------|-------|---------|
| P0 | Raise MaxConcurrent 10->50 | LOW | 30-60s exit | 12s exit | 18-48s |
| P1 | Context propagation | LOW | N/A | Prerequisite | - |
| P2 | Streaming DNS+TCP | MEDIUM | 8s DNS+TCP | 5s | 3s |
| P3 | Shared http.Transport | LOW | +2-5s overhead | Minimal | 2-5s |
| P4 | Long-lived xray / sharded | MED-HIGH | 3s startup | 0-1s | 2-3s |
| P5 | errgroup unification | LOW | N/A | Cleaner code | - |
| P6 | DNS cache across cycles | LOW-MED | 2-5s DNS | 0.5-1s | 1.5-4s |
| P7 | Embedded mmdb | MEDIUM | 1-2s geo | <0.1s | 1-2s |
| P8 | Incremental refresh | HIGH | Full probe | Partial | 20-50s |

**With P0+P1+P2+P3 (quick wins): ~25-55s -> ~18-20s**
**With P0-P7 (full pipeline redesign): ~25-55s -> ~13-15s**
**With P0-P8 (incremental refresh): ~25-55s -> ~5-8s for stable subscriptions**

## Architecture: Proposed Pipeline

```
                    ┌─────────────────────────────────────────┐
                    │         Streaming Pipeline               │
                    │                                         │
fetch/parse ─────► │  DNS stage ──ch──► TCP stage ──ch──►    │
(batch)            │  (errgroup    │    (errgroup    │       │
                   │   SetLimit)   │     SetLimit)   │       │
                   │               ▼                  ▼       │
                   │         ┌── alive records channel ──┐  │
                   │         ▼                           ▼  │
                   │  ┌─ xray shard 1 (ports 10801+) ──┐   │
                   │  ├─ xray shard 2 (ports 10901+) ──┤   │  ──► rename/format
                   │  ├─ xray shard 3 (ports 11001+) ──┤   │
                   │  └─ xray shard 4 (ports 11101+) ──┘   │
                   │     (exit-IP probe, MaxConcurrent=50)  │
                   │                  │                      │
                   │            mmdb geo lookup             │
                   └─────────────────────────────────────────┘
```

Key changes from current:
1. DNS+TCP fused into streaming channel pipeline (no barrier)
2. Alive records stream into xray shards as they arrive
3. xray split into 2-4 shards for parallel startup + probing
4. MaxConcurrent raised to 50 per shard
5. mmdb replaces external geo API calls
6. singleflight for DNS and refresh dedup
7. Context threaded through entire pipeline
8. errgroup replaces manual concurrency primitives
