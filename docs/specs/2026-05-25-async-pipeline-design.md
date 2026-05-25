# vless-sub-server: Async Pipeline Design Document

**Date**: 2026-05-25
**Status**: Draft
**Supersedes**: `2026-05-24-async-optimization-design.md` (replaces P0-P8 priorities with revised approach based on `core.Dial()` discovery)

## Executive Summary

Current pipeline: `fetch → parse → DNS → host-geo → xray start → exit-probe → rename → format`. Every stage blocks until the previous completes. With 50 proxies, total refresh takes 20-45s, dominated by exit-IP probing (70-90% of wall time).

**Key findings from research:**

1. `core.Dial()` + `session.SetForcedOutboundTagToContext()` eliminates ALL SOCKS5 inbounds, port allocation, and routing rules. This is the single highest-impact change. The API is marked `xray:api:stable`.
2. Multiple xray instances are UNSAFE due to `InitSystemDialer()` overwriting package-level globals (`dnsClient`, `obm`).
3. `dns.ResolveStream()` already exists but is UNUSED — was built for streaming but never wired up.
4. `internal/probe/probe.go` does NOT exist (TCP probe is inline in main.go or absent), so TCP pre-filtering is a new addition.
5. DNS has an unconditional 500ms sleep in `resolveWithRetry` even on NXDOMAIN.

**Estimated impact:**

| Scenario | Current | After P0-P2 | After P0-P5 |
|----------|---------|-------------|-------------|
| 50 proxies, fast DNS | 20-30s | 12-15s | 8-10s |
| 50 proxies, slow DNS | 30-45s | 15-20s | 10-13s |
| 100 proxies, fast DNS | 40-60s | 15-20s | 10-12s |

---

## Current Architecture Problems

### Timing Breakdown (50 proxies, typical)

| Stage | Time | Notes |
|-------|------|-------|
| Fetch | 2-15s | Already concurrent, limited by subscription servers |
| Parse | <100ms | Negligible |
| DNS Resolve | 2-6s | `resolveWithRetry`: system resolver → miekg/dns → 500ms sleep → miekg/dns retry |
| Host-IP Geo | 1-5s | Single `ip-api.com/batch` POST, blocks before xray starts |
| Xray Start | 1-3s | `DecodeJSONConfig` + `core.New` + `Start`; config grows with proxy count |
| Exit-IP Probe | 12-30s | 12s timeout per dead proxy, MaxConcurrent=50 but port-per-proxy overhead |
| Batch Geo Lookup | 1-5s | Fallback `ip-api.com/batch` inside `ProbeAll`, sequential after all probes |
| Rename + Format | <100ms | Negligible |

### Structural Problems

1. **Monolithic `refreshSubscriptions`** (lines 135-280 in `main.go`): every phase is coupled in one function with no streaming between stages.

2. **SOCKS5 inbound pattern**: Each proxy gets a dedicated SOCKS5 inbound on a sequential port (`findFreePorts`), routing rules map inbound→outbound. This adds:
   - Port allocation overhead (N `net.Listen`+close per cycle)
   - SOCKS5 handshake per probe (extra RTT)
   - Config bloat: N inbounds + N outbounds + N routing rules
   - No dynamic reconfiguration — must `Close()` entire instance and rebuild

3. **No context propagation**: `resolveWithRetry` and `resolveOne` use `context.Background()`, ignoring the 2-minute pipeline timeout. A hung DNS resolution can outlive the pipeline.

4. **Unconditional 500ms sleep** (`dns.go:123`): `resolveWithRetry` always sleeps 500ms before second DNS attempt, even for NXDOMAIN (instant failure). With 30 unique hosts, this adds 15s of pure delay.

5. **Sequential host-IP geo**: `geo.BatchGeoLookup` runs before xray, but only needed as fallback. It blocks xray startup by 1-5s.

6. **Stale-then-wait caching**: `cachedOutput` is a plain `string` variable. Clients hitting `/sub` during refresh get stale data, but the handler calls `refreshSF.Do` which blocks until complete — could serve stale data immediately and swap atomically when ready.

---

## Proposed Changes

### P0: core.Dial() Refactoring — Eliminate SOCKS5 Inbounds

**What to change:**

Replace the SOCKS5 inbound + routing rule pattern with `core.Dial()` + `session.SetForcedOutboundTagToContext()`.

**Files:** `internal/exitprobe/exitprobe.go` (major refactor)

**Current pattern** (lines 69-103, 142-167):
```go
// StartWithProxies: build N inbounds + N outbounds + N routing rules
// findFreePorts(N) — allocate N TCP listeners
// probeSingle: dial SOCKS5 proxy per proxy index
port := ep.socksPorts[idx]
proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
transport.Proxy = http.ProxyURL(proxyURL)
client.Do(req) // SOCKS5 handshake overhead
```

**New pattern:**
```go
func (ep *ExitProber) StartWithProxies(records []parse.ProxyRecord) error {
    // Build config with ONLY outbounds (no inbounds, no routing rules)
    configJSON := buildOutboundOnlyConfig(records)
    xrayConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
    if err != nil {
        return fmt.Errorf("decode xray config: %w", err)
    }
    coreConfig, err := xrayConfig.Build()
    if err != nil {
        return fmt.Errorf("build xray config: %w", err)
    }
    instance, err := core.New(coreConfig)
    if err != nil {
        return fmt.Errorf("create xray instance: %w", err)
    }
    if err := instance.Start(); err != nil {
        return fmt.Errorf("start xray instance: %w", err)
    }
    ep.instance = instance
    ep.proxyTags = make([]string, len(records))
    for i := range records {
        ep.proxyTags[i] = fmt.Sprintf("proxy_%d_out", i)
    }
    return nil
}

func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
    outboundTag := ep.proxyTags[idx]

    transport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
            host, portStr, _ := net.SplitHostPort(addr)
            port, _ := strconv.Atoi(portStr)
            dest := net.TCPDestination(net.ParseAddress(host), net.Port(port))
            return core.Dial(ctx, ep.instance, dest)
        },
    }
    // ... use transport directly, no SOCKS5 proxy
}
```

**Why it matters:**
- Eliminates `findFreePorts()` entirely — no port allocation, no `net.Listen` per proxy
- Eliminates N SOCKS5 inbounds and N routing rules from config — smaller config, faster xray startup
- Eliminates SOCKS5 handshake per probe — direct `core.Dial` returns `net.Conn`
- Simpler config: only outbounds + a single "direct" freedom outbound needed
- Enables long-lived xray instance (no inbound port conflicts on reconfiguration)

**Config simplification** — `buildOutboundOnlyConfig`:
```json
{
  "log": {"loglevel": "warning"},
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "proxy_0_out", "protocol": "vless", "settings": {...}, "streamSettings": {...}},
    {"tag": "proxy_1_out", "protocol": "trojan", "settings": {...}, "streamSettings": {...}}
  ]
}
```
No `inbounds`, no `routing` section — the dispatcher uses `SetForcedOutboundTagToContext` to route.

**Risk:** LOW. `core.Dial` is `xray:api:stable`. `SetForcedOutboundTagToContext` is used in xray's own dispatcher (`app/dispatcher/default.go:457`). The forced outbound tag bypasses routing rules entirely.

**Estimated savings:** 1-2s config build + parse (smaller config), 0.5-1s per probe round (no SOCKS5 handshake), eliminates port allocation overhead entirely.

---

### P1: Streaming Pipeline with Channel-Based Stage Overlap

**What to change:**

Replace the monolithic `refreshSubscriptions()` with a streaming pipeline where fetch→parse→DNS overlap, and host-IP geo runs concurrently with xray startup.

**Files:** `cmd/vless-sub-server/main.go` (major rewrite), `internal/dns/dns.go` (use existing `ResolveStream`), `internal/fetch/fetch.go` (add `FetchStream`)

**Current flow** (sequential, all-or-nothing barriers):
```
fetch(all) → parse(all) → DNS(all) → hostGeo(all) → xray start → probeAll → rename → format
```

**New flow** (streaming, stages overlap):
```
fetchCh ◄── FetchSubscriptions (stream per URL)
  │
  ▼ (as each FetchResult arrives)
parseCh ◄── ParseAllLines (fast, <100ms per batch)
  │
  ▼ (as hostnames become known)
dnsCh ◄── ResolveStream (stream per host)
  │
  ▼ (once all DNS resolved)
  ├──► BatchGeoLookup (concurrent with xray start)
  ├──► xray.StartWithProxies (overlaps with geo)
  │
  ▼ (xray ready + DNS done)
exitProbeCh ◄── ProbeAll (parallel, errgroup)
  │
  ▼
renameCh ◄── RenameAll (fast)
  │
  ▼
format → atomic swap into cachedOutput
```

**Key insight:** fetch+parse+DNS can pipeline, saving 2-10s depending on scenario. Host-IP geo and xray startup can run concurrently, saving 1-5s.

**Implementation pattern:**
```go
func refreshSubscriptions() {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    // Phase 1: Fetch (already concurrent, collect all)
    fetchResults := fetch.FetchSubscriptions(ctx, cfg.SubscriptionURLs, 15*time.Second)

    // Phase 2: Parse (fast, batch)
    var allLines []string
    for _, r := range fetchResults { allLines = append(allLines, r.Lines...) }
    parseResult := parse.ParseAllLines(allLines)
    filtered := parse.ApplyNameFilter(parseResult.Records, cfg.NameInclude, cfg.NameExclude)

    // Phase 3: DNS (streaming)
    hosts := dedupHosts(filtered)
    dnsCh := dns.ResolveStream(ctx, hosts, 20, cfg.DNSTimeout, dnsCache)
    dnsMap := make(map[string]*dns.DNSResult)
    for result := range dnsCh {
        dnsMap[result.Host] = &result
    }

    var resolved []parse.ProxyRecord
    for _, r := range filtered {
        if d, ok := dnsMap[r.Host]; ok && d.IP != "" {
            resolved = append(resolved, r)
        }
    }

    // Phase 4: Geo + Xray startup IN PARALLEL
    var (
        hostGeoMap map[string]*geo.GeoInfo
        ep         *exitprobe.ExitProber
        xrayErr   error
    )
    var g errgroup.Group
    g.Go(func() error {
        var hostIPs []string
        seen := map[string]bool{}
        for _, r := range resolved {
            if d, ok := dnsMap[r.Host]; ok && d.IP != "" && !seen[d.IP] {
                seen[d.IP] = true
                hostIPs = append(hostIPs, d.IP)
            }
        }
        hostGeoMap = geo.BatchGeoLookup(hostIPs, 10*time.Second)
        return nil
    })
    g.Go(func() error {
        ep = exitprobe.NewExitProber(cfg)
        xrayErr = ep.StartWithProxies(resolved)
        return nil
    })
    g.Wait()

    // Phase 5: Exit-IP probe (parallel)
    // ... rest as before
}
```

**Why it matters:** Overlapping host-IP geo with xray startup saves 1-5s. Using `ResolveStream` avoids DNS becoming a barrier. For 100 proxies with slow DNS, this saves 5-10s.

**Risk:** MEDIUM. Requires careful error handling — if xray fails, need to fall back to host-IP geo. `ResolveStream` already exists and is tested, but wiring it up changes pipeline semantics.

**Estimated savings:** 3-10s depending on DNS speed and proxy count.

---

### P2: Fix DNS `resolveWithRetry` — Eliminate Unconditional 500ms Sleep

**What to change:**

Remove the unconditional `time.Sleep(500 * time.Millisecond)` on line 123 of `dns.go`. Replace with conditional retry that only sleeps on transient errors.

**File:** `internal/dns/dns.go`

**Current code** (lines 108-128):
```go
func resolveWithRetry(_ context.Context, host string, timeout time.Duration) (string, bool) {
    if ip := net.ParseIP(host); ip != nil {
        if isPrivateIP(ip) { return host, true }
        return host, false
    }
    if ip, ok := resolveSystem(context.Background(), host); ok {
        return ip, isPrivateIPStr(ip)
    }
    if ip, ok := resolveOne(context.Background(), host, timeout); ok {
        return ip, isPrivateIPStr(ip)
    }
    time.Sleep(500 * time.Millisecond) // ← unconditional!
    if ip, ok := resolveOne(context.Background(), host, timeout); ok {
        return ip, isPrivateIPStr(ip)
    }
    return "", false
}
```

**New code:**
```go
func resolveWithRetry(ctx context.Context, host string, timeout time.Duration) (string, bool) {
    if ip := net.ParseIP(host); ip != nil {
        if isPrivateIP(ip) { return host, true }
        return host, false
    }
    // Fast path: system resolver
    if ip, ok := resolveSystem(ctx, host); ok {
        return ip, isPrivateIPStr(ip)
    }
    // miekg/dns with multiple servers
    if ip, ok := resolveOne(ctx, host, timeout); ok {
        return ip, isPrivateIPStr(ip)
    }
    // Retry with backoff — but only sleep if the error might be transient
    select {
    case <-ctx.Done():
        return "", false
    case <-time.After(200 * time.Millisecond):
    }
    if ip, ok := resolveOne(ctx, host, timeout); ok {
        return ip, isPrivateIPStr(ip)
    }
    return "", false
}
```

**Also fix:** `resolveWithRetry` currently ignores its `ctx` parameter (uses `context.Background()` internally). Thread context through `resolveSystem` and `resolveOne` properly.

**Why it matters:** With 30 unique hosts, 500ms unconditional sleep adds up to 15s of pure delay. Reducing to 200ms with context-aware cancellation saves 9s on worst case.

**Risk:** LOW. Pure improvement, no behavioral change for successful resolutions.

**Estimated savings:** 5-15s on hosts that fail system DNS and need miekg/dns retry.

---

### P3: Atomic Cache Swap — Serve Stale While Refreshing

**What to change:**

Replace `cachedOutput string` with `atomic.Value` so `/sub` returns stale data immediately while a refresh is in progress, and atomically swaps in new data when ready.

**File:** `cmd/vless-sub-server/main.go`

**Current code** (lines 28-33, 294-305):
```go
var (
    cachedOutput string
    lastRefresh  time.Time
    refreshSF    singleflight.Group
)

func handleSub(w http.ResponseWriter, r *http.Request) {
    if cachedOutput == "" {
        refreshSF.Do("refresh", func() (interface{}, error) { ... })
    }
    w.Write([]byte(cachedOutput))
}
```

**New pattern:**
```go
type cachedData struct {
    output     string
    lastRefresh time.Time
}

var cache atomic.Value // stores *cachedData

func handleSub(w http.ResponseWriter, r *http.Request) {
    v := cache.Load()
    if v == nil {
        // First request: block until initial refresh completes
        refreshSF.Do("refresh", func() (interface{}, error) {
            refreshSubscriptions()
            return nil, nil
        })
        v = cache.Load()
    }
    data := v.(*cachedData)
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("X-Last-Refresh", data.lastRefresh.Format(time.RFC3339))
    w.Write([]byte(data.output))
}

// At end of refreshSubscriptions:
cache.Store(&cachedData{output: output, lastRefresh: time.Now()})
```

**Why it matters:** Currently, if a client hits `/sub` during a refresh (which takes 15-45s), `singleflight` blocks them. With atomic swap, they get the previous result instantly, and the new result appears as soon as the refresh completes.

**Risk:** LOW. Standard Go pattern.

**Estimated impact:** Not a time savings, but a latency improvement for concurrent requests during refresh.

---

### P4: Shared `http.Transport` + Body Draining

**What to change:**

1. In `ExitProber`, use a single shared `http.Transport` with connection pooling instead of cloning per probe.
2. Always drain `resp.Body` with `io.Copy(io.Discard, resp.Body)` before `resp.Body.Close()` to enable connection reuse.
3. In `fetch.go`, use a shared `http.Client` (already has a shared `http.Transport`, but it's module-level — make it configurable).

**File:** `internal/exitprobe/exitprobe.go`

**Current code** (lines 154-157):
```go
proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
transport := ep.transport.Clone() // ← clone per probe, loses idle conns
transport.Proxy = http.ProxyURL(proxyURL)
client := &http.Client{Transport: transport}
```

**With core.Dial() pattern, this becomes:**
```go
transport := &http.Transport{
    DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
        ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
        host, portStr, _ := net.SplitHostPort(addr)
        port, _ := strconv.Atoi(portStr)
        dest := net.TCPDestination(net.ParseAddress(host), net.Port(port))
        return core.Dial(ctx, ep.instance, dest)
    },
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 20,
    IdleConnTimeout:      90 * time.Second,
}
```

**Add body draining** (in `probeSingle` and `probeCFTrace`):
```go
body, err := io.ReadAll(resp.Body)
// ... process body ...
io.Copy(io.Discard, resp.Body) // drain any remaining bytes
resp.Body.Close()
```

**Why it matters:** Without draining, HTTP/1.1 connections cannot be reused, causing port exhaustion under load and extra TCP+TLS handshakes per probe.

**Risk:** LOW. Standard HTTP connection pooling.

**Estimated savings:** 0.5-2s per probe round under high concurrency (reduced TCP/TLS overhead).

---

### P5: Long-Lived Xray Instance

**What to change:**

Keep a single xray-core instance alive across refresh cycles instead of creating and destroying it every 30 minutes.

**File:** `internal/exitprobe/exitprobe.go`, `cmd/vless-sub-server/main.go`

**Current pattern** (in `refreshSubscriptions`):
```go
ep := exitprobe.NewExitProber(cfg)
if err := ep.StartWithProxies(resolved); err != nil { ... }
exitResults := ep.ProbeAll(ctx, resolved)
ep.Stop() // ← destroy instance
```

**New pattern:**
```go
// Create once at server startup (in main)
ep := exitprobe.NewExitProber(cfg)

// Per refresh: reconfigure outbounds
ep.Reconfigure(resolved) // AddOutboundHandler for each proxy, or rebuild config
exitResults := ep.ProbeAll(ctx, resolved)
ep.CleanupProxies() // Remove outbound handlers, but keep instance alive
```

**Challenge:** xray-core's `AddOutboundHandler()` / `RemoveHandler()` on `outbound.Manager` exist but `RemoveHandler` does NOT close the handler (confirmed xray-core bug). Must track and close handlers manually.

**With core.Dial() pattern**, the config is much simpler (only outbounds), so rebuilding config is fast. Two approaches:

1. **Full rebuild** (simpler): `Close()` old instance → `New()` + `Start()` with new outbounds. With P0 (no inbounds, no routing), config is ~3x smaller, startup is ~1s.
2. **Dynamic reconfiguration** (advanced): Use `AddOutboundHandler()` to add, manually close+remove to clean up. Requires tracking handler lifecycle.

**Recommendation:** Start with full rebuild (simpler). With P0's simplified config, rebuild takes <1s vs 2-3s for current config.

**Why it matters:** Eliminates 1-3s of xray startup on each refresh. For the dynamic approach, also eliminates config build + parse time.

**Risk:** MEDIUM for dynamic reconfiguration (xray-core bug in `RemoveHandler`). LOW for full rebuild with simplified config.

**Estimated savings:** 1-3s per refresh cycle.

---

## Architecture: New Streaming Pipeline

```
                              ┌──────────────────────────────────────────────────────────┐
                              │                    refreshSubscriptions()                │
                              │                                                          │
  SUB URLS                    │  ┌─────────┐   ┌───────┐   ┌────────────────┐          │
  ──────────► Fetch (parallel) │  │ ParseAll │   │ DNS   │   │                │          │
                              │  │  Lines   │──►│Stream │──►│  BatchGeoLookup│──┐      │
                              │  │ (fast)   │   │(chan)  │   │  (concurrent)  │  │      │
                              │  └─────────┘   └───────┘   └────────────────┘  │      │
                              │                                    │             │      │
                              │                              resolved[]       │      │
                              │                                    │             │      │
                              │                    ┌─────────────┼─────────────┘      │
                              │                    │  Xray.StartWithProxies (core.Dial) │
                              │                    │         (concurrent w/ geo)        │
                              │                    │                                    │
                              │              ┌─────┴──────┐                             │
                              │              │  ProbeAll   │                             │
                              │              │ (errgroup)  │                             │
                              │              │  core.Dial  │                             │
                              │              │ per proxy   │                             │
                              │              └─────┬──────┘                             │
                              │                    │                                    │
                              │              ┌─────┴──────┐                             │
                              │              │  RenameAll  │                             │
                              │              │  + Format   │                             │
                              │              └─────┬──────┘                             │
                              │                    │                                    │
                              │           atomic.Store(&cache)                        │
                              │                    │                                    │
                              └────────────────────┼────────────────────────────────────┘
                                                   │
                                            GET /sub ◄── reads atomic.Value, serves stale while refreshing
```

**Key differences from current:**

1. **No SOCKS5 inbounds** — `core.Dial()` with `SetForcedOutboundTagToContext` routes directly
2. **DNS streams** — `ResolveStream` produces results as they arrive, not after all resolve
3. **Geo overlaps xray start** — `BatchGeoLookup` runs concurrently with `StartWithProxies`
4. **Atomic cache swap** — clients never block on refresh
5. **Simpler xray config** — only outbounds, no inbounds/routing
6. **Context propagation** — 2-minute timeout cancels all in-flight work

---

## What NOT to Do

### 1. Multiple xray-core instances

`InitSystemDialer()` (`transport/internet/dialer.go:285`) overwrites package-level `dnsClient` and `obm` variables. Creating a second xray instance breaks the first instance's DNS resolution and freedom outbound. Use a SINGLE instance with `core.Dial()` + forced outbound tags.

### 2. sing-box migration

The project already uses xray-core as a Go library with deep integration (`buildOutbound`, `buildStreamSettings`, `vlessEncryption`). Migrating to sing-box would require rewriting all outbound config builders and losing the `core.Dial()` optimization. Not worth it.

### 3. Sharded xray instances

Same problem as #1 — multiple instances clobber global state. The `core.Dial()` approach makes sharding unnecessary since each probe gets its own `net.Conn` via `DialContext` with a forced outbound tag.

### 4. Dynamic handler addition/removal (P5 advanced)

`outbound.Manager.RemoveHandler(ctx, tag)` does NOT close the handler (xray-core bug). Manual close tracking is required. This is a fragile approach — prefer full rebuild with simplified config (P0 makes this fast enough).

### 5. Embedded mmdb for geo lookup

Adding ~60MB to binary size is not justified when `ip-api.com/batch` handles 100 IPs in a single request. The batch API already runs inside `ProbeAll` for fallback geo. Re-evaluate if external API rate limits become a problem.

### 6. Incremental subscription diffing (for now)

Caching previous results and only probing new proxies is valuable but requires persistent state (disk or DB). This is a Phase 3 optimization after the streaming pipeline is stable.

---

## Implementation Phases

### Phase 1: Quick Wins (P0 + P2 + P3 + P4)

**Goal:** Reduce typical refresh from 30-45s to 12-15s.

| Change | Effort | File |
|--------|--------|------|
| P0: core.Dial() refactoring | HIGH | `internal/exitprobe/exitprobe.go` |
| P2: Fix DNS sleep + context | LOW | `internal/dns/dns.go` |
| P3: Atomic cache swap | LOW | `cmd/vless-sub-server/main.go` |
| P4: Shared transport + body drain | LOW | `internal/exitprobe/exitprobe.go` |

**Implementation order:** P2 → P3 → P4 → P0

Rationale: P2 and P3 are low-risk, independent changes. P4 is a minor fix. P0 is the highest-impact change but requires the most work — do it last in Phase 1 so the other improvements are already in place.

**P0 implementation steps:**
1. Add `proxyTags []string` field to `ExitProber` (replaces `socksPorts map[int]int`)
2. Write `buildOutboundOnlyConfig()` — same `buildOutbound` logic, but no inbounds, no routing rules, only outbounds
3. Rewrite `probeSingle` to use `core.Dial()` with `session.SetForcedOutboundTagToContext`
4. Remove `findFreePorts()`, `xrayInbound`, `xrayRoutingRule` types
5. Update `StartWithProxies` to use new config builder
6. Test: verify forced outbound tag routes through correct proxy

### Phase 2: Streaming Pipeline (P1)

**Goal:** Overlap fetch+parse+DNS with xray startup for additional 3-10s savings.

| Change | Effort | File |
|--------|--------|------|
| P1: Channel-based pipeline | MEDIUM-HIGH | `cmd/vless-sub-server/main.go`, `internal/fetch/fetch.go`, `internal/dns/dns.go` |

**Implementation steps:**
1. Wire up `dns.ResolveStream` in `refreshSubscriptions`
2. Run `BatchGeoLookup` and `StartWithProxies` concurrently via `errgroup`
3. Add `FetchStream` to `fetch.go` that returns a channel
4. Restructure `refreshSubscriptions` into clear pipeline stages with error propagation

### Phase 3: Advanced Optimizations (P5 + incremental refresh)

**Goal:** Sub-10s refreshes for stable subscriptions.

| Change | Effort | File |
|--------|--------|------|
| P5: Long-lived xray instance | MEDIUM | `internal/exitprobe/exitprobe.go`, `cmd/vless-sub-server/main.go` |
| Incremental refresh | HIGH | New: `internal/cache/probe_cache.go` |

Long-lived xray instance is viable once P0 (core.Dial) is in place — config rebuild is fast because it's only outbounds. Incremental refresh requires a cache keyed by `(host, port, UUID)` that persists between refresh cycles, with a staleness threshold for re-probing unchanged proxies.

---

## Test Coverage Gap

Current code has **zero tests** for pipeline orchestration. Before Phase 1:

1. Add integration test that exercises `refreshSubscriptions` with a mock subscription server
2. Add unit test for `buildOutboundOnlyConfig` verifying correct outbound tags
3. Add unit test for `core.Dial` routing: verify that `SetForcedOutboundTagToContext` routes through the correct outbound
4. Add unit test for DNS `resolveWithRetry` context cancellation

This is critical because the core.Dial refactoring (P0) changes the fundamental xray integration pattern.