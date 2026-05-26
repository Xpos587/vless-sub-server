# Async Pipeline Design for vless-sub-server

**Goal:** Overlap pipeline stages and eliminate blocking bottlenecks so refresh completes 2-5x faster and never blocks client requests.

**Current pipeline:** `fetch → parse → DNS(all) → xray-probe(all) → rename → format` — fully sequential between stages.

---

## 1. Pipeline Overlap: Streaming Stages

Current: each stage waits for the previous to fully complete. Proposed: stages communicate via channels, processing items as they arrive.

### Dependency Analysis

| Stage | Input | Can Start Streaming? |
|-------|-------|---------------------|
| Fetch | URLs (known upfront) | Already parallel |
| Parse | Lines from fetch | Yes — parse as lines arrive |
| DNS | Hosts from parse | Yes — resolve as hosts appear |
| Xray-probe | All resolved records | **No** — xray needs all outbounds at instance start |
| Rename | Probed records with geo | Yes — rename as probes complete |
| Format | All renamed entries | **No** — need count for header |

Key constraint: **xray-core `core.New()` requires all outbounds at config time.** Cannot add outbounds to a running instance. So DNS → probe transition must buffer.

### Proposed Architecture: Channel-Based Pipeline

```
fetchCh → parseCh → dnsCh → [buffer] → xray-probe(all) → probeCh → rename → format
```

Stages 1-3 (fetch, parse, DNS) overlap via channels. Stage 4 (probe) still batched but starts earlier because DNS results arrive incrementally. Stages 5-6 (rename, format) happen after probe.

**Estimated overlap gain:** 30-60% of DNS time overlaps with fetch+parse tail.

### Implementation Pattern

```go
// Stage 1: Fetch → channel of lines
func FetchStream(ctx context.Context, urls []string) <-chan string {
    out := make(chan string, 100)
    go func() {
        defer close(out)
        g, ctx := errgroup.WithContext(ctx)
        g.SetLimit(len(urls))
        for _, u := range urls {
            u := u
            g.Go(func() error {
                lines := fetchSingle(ctx, u)
                for _, l := range lines {
                    select {
                    case out <- l:
                    case <-ctx.Done():
                        return ctx.Err()
                    }
                }
                return nil
            })
        }
        g.Wait()
    }()
    return out
}

// Stage 2: Parse lines from channel → channel of ProxyRecord
func ParseStream(ctx context.Context, in <-chan string) <-chan parse.ProxyRecord {
    out := make(chan parse.ProxyRecord, 50)
    go func() {
        defer close(out)
        for line := range in {
            if rec := parseLine(line); rec != nil {
                select {
                case out <- *rec:
                case <-ctx.Done():
                    return
                }
            }
        }
    }()
    return out
}

// Stage 3: DNS resolve from channel → channel of resolved record
func DNSStream(ctx context.Context, in <-chan parse.ProxyRecord, ...) <-chan DNSResult {
    // ... errgroup with semaphore, dedup by host
}
```

---

## 2. DNS Resolver Racing (Happy Eyeballs)

**Current:** `resolveWithRetry` tries resolvers sequentially — worst case 5s(system) + 2s×3(resolvers) + 200ms + retry = ~13s per host.

**Proposed:** Race all resolvers concurrently, take first success.

```go
func resolveRacing(ctx context.Context, host string, timeout time.Duration) (string, bool) {
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()

    first := make(chan struct{ ip string; priv bool }, 1)
    var wg sync.WaitGroup

    racers := []func(context.Context) (string, bool){
        func(ctx context.Context) (string, bool) { return resolveSystem(ctx, host) },
        func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "100.100.100.100:53", "udp") },
        func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "8.8.8.8:53", "tcp") },
        func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "1.1.1.1:53", "tcp") },
        func(ctx context.Context) (string, bool) { return resolveDoH(ctx, host, "https://cloudflare-dns.com/dns-query") },
        func(ctx context.Context) (string, bool) { return resolveDoH(ctx, host, "https://dns.google/dns-query") },
    }

    for _, r := range racers {
        wg.Add(1)
        go func(racer func(context.Context) (string, bool)) {
            defer wg.Done()
            if ip, ok := racer(ctx); ok && ip != "" {
                select {
                case first <- struct{ ip string; priv bool }{ip, isPrivateIPStr(ip)}:
                default:
                }
            }
        }(r)
    }

    go func() { wg.Wait(); close(first) }()

    if r, ok := <-first; ok {
        return r.ip, r.priv
    }
    return "", false
}
```

**DoH racer** (no extra library, ~20 lines):
```go
func resolveDoH(ctx context.Context, host, dohURL string) (string, bool) {
    u := fmt.Sprintf("%s?name=%s&type=A", dohURL, host)
    req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
    req.Header.Set("Accept", "application/dns-json")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return "", false }
    defer resp.Body.Close()
    var dohResp struct {
        Answer []struct{ Data string `json:"data"` } `json:"Answer"`
    }
    if json.NewDecoder(resp.Body).Decode(&dohResp) != nil { return "", false }
    for _, a := range dohResp.Answer {
        if net.ParseIP(a.Data) != nil { return a.Data, false }
    }
    return "", false
}
```

**Estimated speedup:** 5-10x for DNS (200ms vs 13s worst case per host).

---

## 3. Offline GeoIP (MaxMind GeoLite2)

**Current:** `batchGeoLookup` → HTTP POST to ip-api.com (10s timeout, HTTP-only, rate-limited). Plus per-proxy ipwho.is during exit probing.

**Proposed:** Local `.mmdb` files. Lookup in ~1-5 microseconds per IP. Eliminates all geo API calls.

```go
import "github.com/oschwald/maxminddb-golang"

type GeoIPDB struct {
    cityDB *maxminddb.Reader
    asnDB  *maxminddb.Reader
}

func (db *GeoIPDB) Lookup(ipStr string) *geo.GeoInfo {
    ip := net.ParseIP(ipStr)
    if ip == nil { return nil }

    var city struct {
        Country struct{ ISOCode string `maxminddb:"iso_code"` } `maxminddb:"country"`
        City    struct{ Names map[string]string `maxminddb:"names"` } `maxminddb:"city"`
    }
    if err := db.cityDB.Lookup(ip, &city); err != nil { return nil }

    var asn struct {
        AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
    }
    db.asnDB.Lookup(ip, &asn)

    return &geo.GeoInfo{
        CountryCode: city.Country.ISOCode,
        City:        city.City.Names["en"],
        ISP:         asn.AutonomousSystemOrganization,
        IP:          ipStr,
    }
}
```

**Database files:**
- `GeoLite2-City.mmdb` (~70MB) — country, city
- `GeoLite2-ASN.mmdb` (~8MB) — ISP/ASN
- Free with MaxMind account registration
- Auto-download at startup or bundle in container image

**Alternative (no registration):** IP2Location LITE databases — Apache-2.0, redistributable, no account needed.

**Impact:** Remove `batchGeoLookup` stage entirely. Inline geo lookup in `probeSingle` after getting exit IP. ~10000x speedup for geo step, removes network dependency.

---

## 4. Async Refresh: Stale-While-Revalidate

**Current:** Periodic ticker triggers full refresh. 503 if cache empty. singleflight prevents concurrent refreshes.

**Proposed:** Never return 503. Always serve previous result (if exists) while refreshing in background.

```go
type cachedData struct {
    output      string
    lastRefresh time.Time
}

var (
    cache     atomic.Value
    refreshing atomic.Int32 // 0=idle, 1=refreshing
)

func handleSub(w http.ResponseWriter, r *http.Request) {
    v := cache.Load()
    if v == nil {
        // First request ever — trigger refresh and wait briefly
        triggerRefresh()
        select {
        case <-time.After(5 * time.Second):
            v = cache.Load() // check again
        }
        if v == nil {
            w.WriteHeader(http.StatusServiceUnavailable)
            w.Write([]byte("# initializing...\n"))
            return
        }
    }

    data := v.(*cachedData)
    // If stale (> refresh interval), trigger background refresh but serve current data
    if time.Since(data.lastRefresh) > cfg.RefreshInterval {
        go triggerRefresh()
    }
    serveCached(w, data)
}

func triggerRefresh() {
    if !refreshing.CompareAndSwap(0, 1) {
        return // already refreshing
    }
    go func() {
        defer refreshing.Store(0)
        refreshSubscriptions()
    }()
}
```

**Benefits:**
- Client never waits for refresh
- Stale data served immediately, fresh data available on next request
- Background refresh doesn't block HTTP handler

### Incremental Refresh (Phase 2)

Instead of re-probing ALL proxies every 30 minutes:
1. Re-fetch subscriptions (fast, ~2s)
2. Diff parsed records against previous set
3. Only probe **new or changed** proxies
4. Carry forward results for unchanged proxies

```go
type PreviousState struct {
    Records map[string]*ExitProbeResult // key: host:port:protocol
    Output  string
}

func refreshIncremental(prev *PreviousState, newRecords []parse.ProxyRecord) {
    var toProbe []parse.ProxyRecord
    for _, r := range newRecords {
        key := dedupKey(r)
        if prev.Records[key] == nil {
            toProbe = append(toProbe, r) // new proxy
        }
    }
    // Only probe new ones, reuse cached results for the rest
}
```

**Estimated speedup:** If 90% of proxies unchanged, probe phase drops from 100% to ~10%.

---

## 5. Xray-Probe Optimizations

### 5A. Reuse Xray Instance Across Refreshes

Current: `StartWithProxies` → `core.New` → `Start` → `ProbeAll` → `Close`. Full lifecycle per refresh.

Proposed: Keep xray instance alive, only rebuild outbounds when proxy list changes significantly.

**Challenge:** xray-core doesn't support adding/removing outbounds from a running instance. Must stop → rebuild → start.

**Alternative:** Pre-create xray instance at startup with a SOCKS5 inbound per proxy. On refresh, only restart if proxy list changed.

### 5B. Batched Probe Start

Start probing as soon as first DNS results arrive, don't wait for all DNS:

```go
const MIN_PROBE_BATCH = 10

resolved := collectFromChannel(dnsCh, MIN_PROBE_BATCH, 2*time.Second)
// Start xray with whatever we have so far
ep := exitprobe.NewExitProber(cfg)
ep.StartWithProxies(resolved)
results1 := ep.ProbeAll(ctx, resolved)
ep.Stop()

// Collect remaining DNS results and probe them in second batch
remaining := collectRemaining(dnsCh)
if len(remaining) > 0 {
    ep2 := exitprobe.NewExitProber(cfg)
    ep2.StartWithProxies(remaining)
    results2 := ep2.ProbeAll(ctx, remaining)
    ep2.Stop()
    merge(results1, results2)
}
```

### 5C. Pre-flight TCP Check Before Xray Probe

Skip xray probe for hosts that fail TCP connection test. TCP check is ~100ms, xray probe is ~12s.

```go
// Quick TCP check first
if !tcpReachable(host, port, 3*time.Second) {
    continue // skip expensive xray probe
}
```

This is what the Bun version does. In the Go version we removed TCP probe, but adding a quick pre-check could filter 30-50% of dead proxies before the expensive xray phase.

---

## 6. Existing Projects Research

### subconverter (tindy2013/subconverter)
- C++ with Go wrapper, most popular sub converter
- Architecture: fetch → parse → convert → output (sequential)
- No exit-IP probing — converts format only
- Not relevant for our probing use case

### proxy-pool / proxy-checker projects (GitHub)
- Most use simple TCP connect checks, not xray-core
- Pattern: goroutine pool + channel-based producer/consumer
- Common: `chan Proxy` → worker pool of N goroutines → results channel

### xray-core as library
- Very few projects embed xray-core as library
- Most use xray-core as subprocess (xray run -c config.json)
- Our approach (in-process `core.Dial`) is unique and faster for startup but requires full rebuild for config changes

### Key takeaway
No existing project does exactly what we do. The Bun/Windmill version is the closest analog. Our main competitive advantage is in-process xray-core probing. The main optimization opportunity is in pipeline overlap and DNS/geo speed.

---

## 7. Implementation Priority

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| **P0** | Stale-while-revalidate | Low | High — never block clients |
| **P1** | DNS resolver racing | Medium | High — 5-10x DNS speedup |
| **P1** | Offline GeoIP (GeoLite2) | Medium | High — eliminate geo API calls |
| **P2** | Channel-based fetch→parse→DNS | Medium | Medium — overlap pipeline stages |
| **P2** | Pre-flight TCP check | Low | Medium — skip ~30-50% of dead proxies |
| **P3** | Incremental refresh | High | High — but complex |
| **P3** | Batched probe start | Medium | Low — marginal gain |
| **P3** | Reuse xray instance | High | Low — xray API limitation |

### Recommended Phase 1 (Quick Wins)
1. Stale-while-revalidate (never return 503)
2. DNS resolver racing with DoH
3. Offline GeoLite2 database
4. Pre-flight TCP check before xray probe

### Recommended Phase 2 (Pipeline Overhaul)
5. Channel-based streaming fetch→parse→DNS
6. Incremental refresh with cached results

---

## 8. New Dependencies

| Package | Purpose | Size |
|---------|---------|------|
| `github.com/oschwald/maxminddb-golang` | Offline GeoIP lookup | Small, pure Go, no CGO |
| (no new dep for DoH) | Uses stdlib `net/http` | — |
| (no new dep for racing) | Uses existing `miekg/dns` | — |

## 9. New Config

| Variable | Default | Description |
|----------|---------|-------------|
| `GEO_DB_DIR` | `/usr/local/share/xray` | Path to GeoLite2 .mmdb files |
| `MAXMIND_LICENSE_KEY` | `""` | Optional, for auto-downloading GeoLite2 |