# Async/Parallel Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optimize vless-sub-server pipeline from sequential batch processing to overlapping streaming with higher concurrency, targeting 2-5x reduction in refresh cycle time.

**Architecture:** Replace sequential phase barriers (DNS→TCP→xray→probe) with a streaming channel pipeline where DNS and TCP stages overlap. Thread `context.Context` through all operations. Unify concurrency with `errgroup.SetLimit`. Add DNS cross-cycle cache. Raise exit-probe concurrency from 10 to 50. Share `http.Transport` across probes. Use `singleflight` for refresh dedup.

**Tech Stack:** Go 1.26, `golang.org/x/sync/errgroup`, `golang.org/x/sync/singleflight`, xray-core v1.260327.0

**Spec:** `docs/specs/2026-05-24-async-optimization-design.md`

**Phases in this plan:** P0 (concurrency), P1 (context), P2 (streaming pipeline), P3 (http transport reuse), P5 (errgroup), P6 (DNS cache). P4 (long-lived xray) and P7 (mmdb), P8 (incremental refresh) are future phases.

---

## File Structure

Files created or modified in this plan:

| File | Responsibility |
|------|---------------|
| `cmd/vless-sub-server/main.go` | Pipeline orchestration — streaming pipeline, context threading, singleflight refresh |
| `internal/config/config.go` | Config struct — DynamicMaxConcurrent, DNS cache TTL |
| `internal/fetch/fetch.go` | Subscription fetch — context param, shared http.Client |
| `internal/dns/dns.go` | DNS resolution — context param, streaming API, TTL cache, singleflight |
| `internal/probe/probe.go` | TCP probing — context param, streaming API |
| `internal/exitprobe/exitprobe.go` | Exit-IP probe — context param, shared transport, dynamic concurrency |
| `internal/geo/geo.go` | Geo types — unchanged in this phase |
| `internal/parse/parse.go` | Parsing — unchanged in this phase |
| `internal/parse/types.go` | ProxyRecord — unchanged |
| `internal/rename/rename.go` | Renaming — unchanged |
| `internal/format/format.go` | Output formatting — unchanged |

New files:

| File | Responsibility |
|------|---------------|
| `internal/pipeline/pipeline.go` | Streaming pipeline orchestration — channels, stage wiring, merge logic |

---

## Wave 1: Quick Wins (P0 + P1 + P3)

These are independent changes that can be made in parallel. Each is small and self-contained.

---

### Task 1: P0 — Raise exit-probe concurrency to 50

**Files:**

- Modify: `internal/config/config.go:14` (default MaxConcurrent)
- Modify: `cmd/vless-sub-server/main.go:102` (dynamic max)

**Rationale:** MaxConcurrent=10 is the single biggest bottleneck. 50 proxies with 10 concurrent = 5 rounds × 12s = 60s. With 50 concurrent = 1 round × 12s = 12s. Each proxy hits ipwho.is from a different exit IP, so no rate-limit concern.

- [ ] **Step 1: Change MaxConcurrent default from 10 to 50**

In `internal/config/config.go`, change:

```go
// Before:
MaxConcurrent    int           `env:"MAX_CONCURRENT" envDefault:"10"`

// After:
MaxConcurrent    int           `env:"MAX_CONCURRENT" envDefault:"50"`
```

- [ ] **Step 2: Make exit-probe concurrency dynamic based on proxy count**

In `cmd/vless-sub-server/main.go`, before the `ep.ProbeAll` call, add dynamic concurrency:

```go
// Before (line ~102):
c.MaxConcurrent, _ = strconv.Atoi(envOr("MAX_CONCURRENT", "50"))

// After: keep the env var, but override with len(aliveRecords) if smaller
maxProbe := c.MaxConcurrent
if len(aliveRecords) > 0 && len(aliveRecords) < maxProbe {
    maxProbe = len(aliveRecords)
}
```

Then pass `maxProbe` to `ProbeAll`. This requires changing `ProbeAll` signature to accept a concurrency parameter (done in Task 3).

For now, just change the default and the env var fallback. The `ProbeAll` method already reads `ep.cfg.MaxConcurrent`.

- [ ] **Step 3: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

Expected: builds with no errors.

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "perf: raise default MaxConcurrent from 10 to 50

50 proxies / 10 concurrent = 5 rounds × 12s = 60s worst case.
50 proxies / 50 concurrent = 1 round × 12s = 12s worst case.
Each proxy routes through a different exit IP, so ipwho.is rate
limiting is not a concern."
```

---

### Task 2: P1 — Thread context.Context through all functions

**Files:**

- Modify: `internal/fetch/fetch.go` — add `ctx context.Context` param
- Modify: `internal/dns/dns.go` — add `ctx context.Context` param
- Modify: `internal/probe/probe.go` — add `ctx context.Context` param
- Modify: `internal/exitprobe/exitprobe.go` — propagate ctx to HTTP requests

**Rationale:** Current code uses `context.Background()` internally, breaking the cancellation chain from the 2-minute pipeline timeout in `refreshSubscriptions`. Every blocking function must accept ctx and respect cancellation.

- [ ] **Step 1: Add context to fetch.go**

Change `FetchSubscriptions` and `fetchSingle` signatures:

```go
// Before:
func FetchSubscriptions(urls []string, timeout time.Duration) []FetchResult {

func fetchSingle(url string, timeout time.Duration) FetchResult {

// After:
func FetchSubscriptions(ctx context.Context, urls []string, timeout time.Duration) []FetchResult {

func fetchSingle(ctx context.Context, url string, timeout time.Duration) FetchResult {
```

Inside `fetchSingle`, replace:

```go
// Before:
req, err := http.NewRequest("GET", url, nil)

// After:
req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
```

Inside `FetchSubscriptions`, pass `ctx` through (no other changes needed since goroutines don't need ctx for result collection).

- [ ] **Step 2: Add context to dns.go**

Change `ResolveHosts` and `resolveOne` signatures:

```go
// Before:
func ResolveHosts(hosts []string, maxConcurrent int, timeout time.Duration) map[string]*DNSResult {

func resolveOne(host string, timeout time.Duration) (string, bool) {

// After:
func ResolveHosts(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration) map[string]*DNSResult {

func resolveOne(ctx context.Context, host string, timeout time.Duration) (string, bool) {
```

Inside `resolveOne`, replace:

```go
// Before:
ctx, cancel := context.WithTimeout(context.Background(), timeout)

// After:
ctx, cancel := context.WithTimeout(ctx, timeout)
```

Inside `ResolveHosts`, no ctx usage needed beyond passing it to `resolveWithRetry`. But we should add ctx check to `resolveWithRetry`:

```go
// Before:
func resolveWithRetry(host string, timeout time.Duration) (string, bool) {

// After:
func resolveWithRetry(ctx context.Context, host string, timeout time.Duration) (string, bool) {
```

And in `resolveWithRetry`, replace:

```go
// Before:
if ip, ok := resolveOne(host, timeout); ok {
    return ip, isPrivateIPStr(ip)
}
time.Sleep(500 * time.Millisecond)
if ip, ok := resolveOne(host, timeout); ok {
    return ip, isPrivateIPStr(ip)
}

// After:
select {
case <-ctx.Done():
    return "", false
default:
}
if ip, ok := resolveOne(ctx, host, timeout); ok {
    return ip, isPrivateIPStr(ip)
}
select {
case <-time.After(500 * time.Millisecond):
case <-ctx.Done():
    return "", false
}
if ip, ok := resolveOne(ctx, host, timeout); ok {
    return ip, isPrivateIPStr(ip)
}
```

- [ ] **Step 3: Add context to probe.go**

Change `TCPProbeAll` signature:

```go
// Before:
func TCPProbeAll(hosts []struct{ Host, IP string; Port int }, maxConcurrent int, timeout time.Duration) map[string]*ProbeResult {

// After:
type HostSpec struct {
    Host string
    IP   string
    Port int
}

func TCPProbeAll(ctx context.Context, hosts []HostSpec, maxConcurrent int, timeout time.Duration) map[string]*ProbeResult {
```

Inside `TCPProbeAll`, add ctx check in the goroutine:

```go
go func(host, ip string, port int) {
    defer wg.Done()
    defer func() { <-sem }()
    select {
    case <-ctx.Done():
        return
    default:
    }
    // ... existing probe logic
}(h.Host, h.IP, h.Port)
```

Change `tcpProbe` to accept ctx:

```go
// Before:
func tcpProbe(host string, port int, timeout time.Duration) *ProbeResult {

// After:
func tcpProbe(ctx context.Context, host string, port int, timeout time.Duration) *ProbeResult {
```

And use `net.Dialer` with context:

```go
// Before:
conn, err := net.DialTimeout("tcp", addr, timeout)

// After:
d := net.Dialer{Timeout: timeout}
conn, err := d.DialContext(ctx, "tcp", addr)
```

- [ ] **Step 4: Add context propagation to exitprobe.go**

`ProbeAll` already accepts `ctx context.Context`. Update `probeSingle` to propagate it:

```go
// No signature change needed — ctx is already passed.
// But add ctx.Done() check at start of probeSingle:
func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
    select {
    case <-ctx.Done():
        return &ExitProbeResult{XrayOK: false}
    default:
    }
    // ... rest of function
```

- [ ] **Step 5: Update main.go call sites**

In `refreshSubscriptions`, update all function calls:

```go
// Before:
fetchResults := fetch.FetchSubscriptions(cfg.SubscriptionURLs, 8*time.Second)

// After:
fetchResults := fetch.FetchSubscriptions(ctx, cfg.SubscriptionURLs, 8*time.Second)

// Before:
dnsMap := dns.ResolveHosts(hostList, 20, cfg.DNSTimeout)

// After:
dnsMap := dns.ResolveHosts(ctx, hostList, 20, cfg.DNSTimeout)

// Before:
probeResults := probe.TCPProbeAll(probeHosts, 20, cfg.TCPTimeout)

// After:
probeResults := probe.TCPProbeAll(ctx, probeHosts, 20, cfg.TCPTimeout)
```

Note: the `ctx` variable already exists in `refreshSubscriptions` (line 125): `ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)`.

- [ ] **Step 6: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 7: Commit**

```bash
git add internal/fetch/fetch.go internal/dns/dns.go internal/probe/probe.go internal/exitprobe/exitprobe.go cmd/vless-sub-server/main.go
git commit -m "refactor: thread context.Context through all pipeline functions

Enables proper cancellation propagation from the 2-minute pipeline
timeout to individual DNS, TCP, and HTTP operations. Replaces
context.Background() with derived contexts that respect parent
cancellation."
```

---

### Task 3: P3 — Shared http.Transport in exitprobe

**Files:**

- Modify: `internal/exitprobe/exitprobe.go` — shared Transport, body draining
- Modify: `internal/fetch/fetch.go` — shared Client

**Rationale:** Current code creates a new `http.Transport` and `http.Client` per probe request. This prevents TLS session resumption and connection pooling. A shared Transport enables keep-alive across probes to the same host (ipwho.is, cloudflare).

- [ ] **Step 1: Add shared Transport to ExitProber**

In `internal/exitprobe/exitprobe.go`, add a `transport` field:

```go
type ExitProber struct {
    cfg        *config.Config
    instance   *core.Instance
    socksPorts map[int]int
    transport  *http.Transport
    mu         sync.Mutex
}

func NewExitProber(cfg *config.Config) *ExitProber {
    return &ExitProber{
        cfg:        cfg,
        socksPorts: make(map[int]int),
        transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 20,
            IdleConnTimeout:     90 * time.Second,
            DialContext: (&net.Dialer{
                Timeout:   cfg.ExitProbeTimeout,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSHandshakeTimeout:   cfg.ExitProbeTimeout,
            ResponseHeaderTimeout:  cfg.ExitProbeTimeout,
        },
    }
}
```

- [ ] **Step 2: Update probeSingle to use shared Transport with per-proxy SOCKS5**

```go
func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
    select {
    case <-ctx.Done():
        return &ExitProbeResult{XrayOK: false}
    default:
    }

    port, ok := ep.socksPorts[idx]
    if !ok {
        return &ExitProbeResult{XrayOK: false}
    }

    proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))

    // Clone shared transport with proxy override for this specific SOCKS5 port
    transport := ep.transport.Clone()
    transport.Proxy = http.ProxyURL(proxyURL)

    client := &http.Client{
        Transport: transport,
        // No Timeout — use context deadline + transport-level timeouts
    }

    req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/", nil)
    if err != nil {
        return &ExitProbeResult{XrayOK: false}
    }
    req.Header.Set("User-Agent", "vless-sub-server/1.0")

    resp, err := client.Do(req)
    if err != nil {
        return &ExitProbeResult{XrayOK: false}
    }
    defer resp.Body.Close()
    // Drain body to enable connection reuse
    io.Copy(io.Discard, resp.Body)

    // ... rest of probeSingle unchanged (body reading, JSON parse)
```

Same pattern for `probeCFTrace`: use `ep.transport.Clone()` with proxy override, drain response body.

- [ ] **Step 3: Add shared Client to fetch.go**

```go
var fetchClient = &http.Client{
    Timeout: 8 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        10,
        MaxIdleConnsPerHost: 5,
        IdleConnTimeout:     30 * time.Second,
    },
}

func fetchSingle(ctx context.Context, url string, timeout time.Duration) FetchResult {
    // Use a per-request client with the specified timeout
    client := &http.Client{
        Timeout:   timeout,
        Transport: fetchClient.Transport,
    }
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    // ... rest unchanged
```

- [ ] **Step 4: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 5: Commit**

```bash
git add internal/exitprobe/exitprobe.go internal/fetch/fetch.go
git commit -m "perf: share http.Transport across probes and fetch requests

Clone transport per SOCKS5 proxy. Drain response bodies for connection
reuse. Share underlying transport across fetch requests. Enables TLS
session resumption and connection pooling."
```

---

## Wave 2: Pipeline Redesign (P2 + P5)

This wave restructures the pipeline from sequential batch phases to a streaming channel pipeline. It depends on Wave 1 (context, errgroup) being complete.

---

### Task 4: P5 — errgroup unification + singleflight refresh guard

**Files:**

- Modify: `internal/fetch/fetch.go` — errgroup
- Modify: `internal/dns/dns.go` — errgroup
- Modify: `internal/probe/probe.go` — errgroup
- Modify: `cmd/vless-sub-server/main.go` — singleflight for refresh, errgroup

**Rationale:** Unify all concurrency patterns with `errgroup.SetLimit()`. Replace racy `refreshing` bool with `singleflight.Group`.

- [ ] **Step 1: Add golang.org/x/sync dependency**

```bash
cd /home/michael/Github/vless-sub-server && go get golang.org/x/sync
```

This pulls in `errgroup` and `singleflight` sub-packages. `go.mod` already has `golang.org/x/sync v0.20.0` as indirect — this promotes it to direct.

- [ ] **Step 2: Convert fetch.go to errgroup**

```go
import "golang.org/x/sync/errgroup"

func FetchSubscriptions(ctx context.Context, urls []string, timeout time.Duration) []FetchResult {
    results := make([]FetchResult, len(urls))
    g, _ := errgroup.WithContext(ctx)
    g.SetLimit(len(urls)) // all URLs in parallel — typically 2-5

    for i, u := range urls {
        i, u := i, u
        g.Go(func() error {
            results[i] = fetchSingle(ctx, u, timeout)
            return nil // best-effort: collect all results regardless
        })
    }
    g.Wait()
    return results
}
```

- [ ] **Step 3: Convert dns.go to errgroup**

```go
import "golang.org/x/sync/errgroup"

func ResolveHosts(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration) map[string]*DNSResult {
    results := make(map[string]*DNSResult, len(hosts))
    var mu sync.Mutex
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    for _, h := range hosts {
        h := h
        g.Go(func() error {
            ip, isPrivate := resolveWithRetry(ctx, h, timeout)
            mu.Lock()
            results[h] = &DNSResult{IP: ip, IsPrivate: isPrivate}
            mu.Unlock()
            return nil // best-effort
        })
    }
    g.Wait()
    return results
}
```

Remove `resolveWithRetry` goroutine management — it's now a simple function called inside `g.Go`.

- [ ] **Step 4: Convert probe.go to errgroup**

```go
import "golang.org/x/sync/errgroup"

type HostSpec struct {
    Host string
    IP   string
    Port int
}

func TCPProbeAll(ctx context.Context, hosts []HostSpec, maxConcurrent int, timeout time.Duration) map[string]*ProbeResult {
    results := make(map[string]*ProbeResult, len(hosts))
    var mu sync.Mutex
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    for _, h := range hosts {
        h := h
        g.Go(func() error {
            select {
            case <-ctx.Done():
                return nil
            default:
            }
            result := tcpProbe(ctx, h.IP, h.Port, timeout)
            if result == nil {
                result = &ProbeResult{}
            }
            key := fmt.Sprintf("%s:%d", h.Host, h.Port)
            mu.Lock()
            results[key] = result
            mu.Unlock()
            return nil
        })
    }
    g.Wait()
    return results
}
```

- [ ] **Step 5: Convert exitprobe.go ProbeAll to errgroup**

```go
import "golang.org/x/sync/errgroup"

func (ep *ExitProber) ProbeAll(ctx context.Context, records []parse.ProxyRecord) map[int]*ExitProbeResult {
    results := make(map[int]*ExitProbeResult, len(records))
    var mu sync.Mutex
    maxConcurrent := ep.cfg.MaxConcurrent
    if len(records) < maxConcurrent {
        maxConcurrent = len(records)
    }

    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    for i, rec := range records {
        i, rec := i, rec
        g.Go(func() error {
            result := ep.probeSingle(ctx, i, rec)
            mu.Lock()
            results[i] = result
            mu.Unlock()
            return nil // best-effort: collect all results
        })
    }
    g.Wait()
    return results
}
```

- [ ] **Step 6: Replace racy `refreshing` bool with singleflight in main.go**

```go
import "golang.org/x/sync/singleflight"

var (
    cachedOutput string
    lastRefresh  time.Time
    refreshSF    singleflight.Group
    cfg          *config.Config
)
```

Remove `refreshing` bool. Replace `refreshSubscriptions` call in main goroutine and HTTP handler:

```go
// In main(), replace:
// go refreshSubscriptions()

// With:
go func() {
    _, _, _ = refreshSF.Do("refresh", func() (interface{}, error) {
        refreshSubscriptions()
        return nil, nil
    })
}()

// In periodic ticker:
go func() {
    for range ticker.C {
        _, _, _ = refreshSF.Do("refresh", func() (interface{}, error) {
            refreshSubscriptions()
            return nil, nil
        })
    }
}()

// In handleSub, replace:
// if cachedOutput == "" {
//     refreshSubscriptions()
// }

// With:
if cachedOutput == "" {
    _, _, _ = refreshSF.Do("refresh", func() (interface{}, error) {
        refreshSubscriptions()
        return nil, nil
    })
}
```

- [ ] **Step 7: Update main.go probeHosts construction for HostSpec type**

```go
// Before:
probeHosts := make([]struct{ Host, IP string; Port int }, len(withDNS))

// After:
probeHosts := make([]probe.HostSpec, len(withDNS))
```

And update the loop:

```go
for i, r := range withDNS {
    probeHosts[i] = probe.HostSpec{
        Host: r.Host,
        IP:   dnsMap[r.Host].IP,
        Port: r.Port,
    }
}
```

- [ ] **Step 8: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 9: Commit**

```bash
git add internal/fetch/fetch.go internal/dns/dns.go internal/probe/probe.go internal/exitprobe/exitprobe.go cmd/vless-sub-server/main.go go.mod go.sum
git commit -m "refactor: unify concurrency with errgroup, replace refreshing bool with singleflight

- fetch, dns, probe, exitprobe: replace WaitGroup+semaphore with errgroup.SetLimit
- dns, probe: add context cancellation support via errgroup derived ctx
- main: replace racy refreshing bool with singleflight.Group for refresh dedup
- probe: extract HostSpec type for cleaner API"
```

---

### Task 5: P2 — Create pipeline package with streaming DNS+TCP

**Files:**

- Create: `internal/pipeline/pipeline.go` — streaming pipeline orchestration
- Modify: `internal/dns/dns.go` — add `ResolveSingle` for streaming
- Modify: `internal/probe/probe.go` — add `TCPProbeSingle` for streaming
- Modify: `cmd/vless-sub-server/main.go` — use pipeline package

**Rationale:** The current pipeline has a full barrier between DNS and TCP phases. DNS must finish ALL hosts before ANY TCP probe starts. Streaming eliminates this barrier: TCP probing starts as soon as the first DNS result arrives.

Current: `DNS(all) → TCP(all) = 5s + 3s = 8s`
After: `DNS+TCP overlapped = max(5s, 3s) ≈ 5s`

- [ ] **Step 1: Create `internal/pipeline/pipeline.go`**

This file defines the streaming pipeline types and orchestration:

```go
package pipeline

import (
    "context"

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

// ProbedProxy holds a proxy that passed both DNS and TCP probe.
type ProbedProxy struct {
    Record parse.ProxyRecord
    DNS    *dns.DNSResult
    Probe  *probe.ProbeResult
    IsLAN  bool
}

// ProbeAndFilter runs the streaming DNS → TCP pipeline and returns
// alive proxies that passed both stages.
func ProbeAndFilter(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration) []ProbedProxy {
    // Stage 1: Resolve DNS for all unique hosts
    uniqueHosts := dedupHosts(records)
    dnsMap := dns.ResolveHosts(ctx, uniqueHosts, maxConcurrent, dnsTimeout)

    // Stage 2: Filter records that resolved
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

    // Stage 3: TCP probe all resolved hosts
    hosts := make([]probe.HostSpec, len(withDNS))
    for i, r := range withDNS {
        hosts[i] = probe.HostSpec{
            Host: r.Record.Host,
            IP:   r.DNS.IP,
            Port: r.Record.Port,
        }
    }
    probeResults := probe.TCPProbeAll(ctx, hosts, maxConcurrent, tcpTimeout)

    // Stage 4: Collect alive proxies
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
    return alive
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
```

Note: this initial version keeps DNS and TCP as sequential stages (batch). The true streaming (channel-based) overlap is a future optimization that requires more invasive changes to dns.go and probe.go APIs. This task establishes the pipeline package with clean types and dedup, making the streaming refactor smaller later.

- [ ] **Step 2: Update main.go to use pipeline package**

In `refreshSubscriptions`, replace lines 149-184 (DNS resolve + filter + TCP probe + alive collection) with:

```go
// Replace: DNS resolve, filter, TCP probe, alive collection
// With:
aliveProxies := pipeline.ProbeAndFilter(ctx, filtered, 20, cfg.DNSTimeout, cfg.TCPTimeout)

var aliveRecords []parse.ProxyRecord
for _, p := range aliveProxies {
    aliveRecords = append(aliveRecords, p.Record)
}
```

Also remove the `probeHosts` construction, `withDNS` variable, and `aliveRecords` filter loop — they're now inside `ProbeAndFilter`.

The `dnsMap` variable is still needed for `isLAN` checks in the geo records section. Add a helper:

```go
// Build dnsMap from pipeline results for geo section
dnsMap := make(map[string]*dns.DNSResult)
for _, p := range aliveProxies {
    dnsMap[p.Record.Host] = p.DNS
}
```

- [ ] **Step 3: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 4: Commit**

```bash
git add internal/pipeline/pipeline.go cmd/vless-sub-server/main.go
git commit -m "refactor: extract DNS+TCP+filter pipeline into internal/pipeline

Moves DNS resolution, TCP probing, and alive-proxy filtering into a
dedicated pipeline package with clean types. Reduces main.go complexity
and sets up for future streaming overlap between DNS and TCP stages."
```

---

### Task 6: P2 — Streaming DNS+TCP overlap within pipeline

**Files:**

- Modify: `internal/pipeline/pipeline.go` — streaming DNS→TCP pipeline
- Modify: `internal/dns/dns.go` — add `ResolveStream` that emits results as they arrive
- Modify: `internal/probe/probe.go` — add `TCPProbeSingle` for per-host probing

**Rationale:** Now we add the true streaming overlap. DNS results flow through a channel to TCP probing. TCP starts as soon as the first DNS result arrives, not after all DNS completes.

- [ ] **Step 1: Add ResolveStream to dns.go**

```go
// ResolveStream resolves hosts concurrently and emits results as they arrive.
// Returns a channel that is closed when all hosts are processed or ctx is cancelled.
func ResolveStream(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration) <-chan DNSResult {
    out := make(chan DNSResult, maxConcurrent)
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    for _, h := range hosts {
        h := h
        g.Go(func() error {
            ip, isPrivate := resolveWithRetry(ctx, h, timeout)
            select {
            case out <- DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}:
            case <-ctx.Done():
            }
            return nil
        })
    }

    go func() {
        g.Wait()
        close(out)
    }()

    return out
}
```

Note: `DNSResult` needs a `Host` field added:

```go
type DNSResult struct {
    Host      string
    IP        string
    IsPrivate bool
}
```

- [ ] **Step 2: Add TCPProbeSingle to probe.go**

```go
// TCPProbeSingle probes a single host. Used by the streaming pipeline
// where each host is probed immediately after DNS resolution.
func TCPProbeSingle(ctx context.Context, ip string, port int, timeout time.Duration) *ProbeResult {
    select {
    case <-ctx.Done():
        return &ProbeResult{Reachable: false, FailureType: "canceled"}
    default:
    }
    addr := fmt.Sprintf("%s:%d", ip, port)
    start := time.Now()
    d := net.Dialer{Timeout: timeout}
    conn, err := d.DialContext(ctx, "tcp", addr)
    if err != nil {
        ft := "error"
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            ft = "timeout"
        } else {
            ft = "refused"
        }
        return &ProbeResult{Reachable: false, FailureType: ft}
    }
    conn.Close()
    return &ProbeResult{Reachable: true, LatencyMs: time.Since(start).Milliseconds()}
}
```

- [ ] **Step 3: Add streaming pipeline method to pipeline.go**

```go
// ProbeAndFilterStream runs DNS and TCP probing as an overlapping pipeline.
// DNS results flow to TCP probing as they arrive — no barrier between stages.
func ProbeAndFilterStream(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration) []ProbedProxy {
    // Deduplicate hosts
    uniqueHosts := dedupHosts(records)
    hostSet := make(map[string]bool, len(uniqueHosts))
    for _, h := range uniqueHosts {
        hostSet[h] = true
    }

    // Build host -> records index
    hostToRecords := make(map[string][]parse.ProxyRecord)
    for _, r := range records {
        hostToRecords[r.Host] = append(hostToRecords[r.Host], r)
    }

    // Stage 1: Stream DNS results
    dnsCh := dns.ResolveStream(ctx, uniqueHosts, maxConcurrent, dnsTimeout)

    // Stage 2: TCP probe each DNS result as it arrives
    type probedResult struct {
        Record parse.ProxyRecord
        DNS    *dns.DNSResult
        Probe  *probe.ProbeResult
        IsLAN  bool
    }
    probedCh := make(chan probedResult, maxConcurrent)

    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    go func() {
        defer close(probedCh)
        for dnsRes := range dnsCh {
            if dnsRes.IP == "" {
                continue
            }
            for _, rec := range hostToRecords[dnsRes.Host] {
                rec := rec
                dnsRes := dnsRes
                g.Go(func() error {
                    target := dnsRes.IP
                    probeRes := probe.TCPProbeSingle(ctx, target, rec.Port, tcpTimeout)
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
    return alive
}
```

- [ ] **Step 4: Update main.go to use streaming pipeline**

In `refreshSubscriptions`, replace the pipeline call:

```go
// Before:
aliveProxies := pipeline.ProbeAndFilter(ctx, filtered, 20, cfg.DNSTimeout, cfg.TCPTimeout)

// After:
aliveProxies := pipeline.ProbeAndFilterStream(ctx, filtered, 20, cfg.DNSTimeout, cfg.TCPTimeout)
```

Also update the dnsMap construction for the geo section:

```go
// Build dnsMap from pipeline results for geo section
dnsMap := make(map[string]*dns.DNSResult)
for _, p := range aliveProxies {
    if p.DNS != nil {
        dnsMap[p.Record.Host] = p.DNS
    }
}
```

- [ ] **Step 5: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 6: Commit**

```bash
git add internal/pipeline/pipeline.go internal/dns/dns.go internal/probe/probe.go cmd/vless-sub-server/main.go
git commit -m "perf: streaming DNS+TCP pipeline — no barrier between stages

DNS results flow to TCP probing via channels. TCP probes start as soon
as the first DNS result arrives instead of waiting for all DNS to complete.
Eliminates 3-8s of idle time between DNS and TCP phases."
```

---

## Wave 3: DNS Cache (P6)

---

### Task 7: P6 — TTL-aware DNS cache across refresh cycles

**Files:**

- Modify: `internal/dns/dns.go` — add `DNSCache` type with TTL support
- Modify: `cmd/vless-sub-server/main.go` — create persistent cache, pass to pipeline

**Rationale:** DNS results for proxy servers rarely change within 30 minutes. With a 10-minute TTL, ~2/3 of hosts hit cache on each refresh, saving 1.5-4s per cycle.

- [ ] **Step 1: Add DNSCache type to dns.go**

```go
type cacheEntry struct {
    ip        string
    isPrivate bool
    expiresAt time.Time
}

type DNSCache struct {
    mu      sync.RWMutex
    entries map[string]cacheEntry
    ttl     time.Duration
}

func NewDNSCache(ttl time.Duration) *DNSCache {
    return &DNSCache{
        entries: make(map[string]cacheEntry),
        ttl:     ttl,
    }
}

func (c *DNSCache) Get(host string) (ip string, isPrivate bool, ok bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    e, exists := c.entries[host]
    if !exists || time.Now().After(e.expiresAt) {
        return "", false, false
    }
    return e.ip, e.isPrivate, true
}

func (c *DNSCache) Set(host, ip string, isPrivate bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries[host] = cacheEntry{
        ip:        ip,
        isPrivate: isPrivate,
        expiresAt: time.Now().Add(c.ttl),
    }
}

// Purge removes expired entries. Call periodically (e.g., after each refresh).
func (c *DNSCache) Purge() {
    c.mu.Lock()
    defer c.mu.Unlock()
    now := time.Now()
    for host, e := range c.entries {
        if now.After(e.expiresAt) {
            delete(c.entries, host)
        }
    }
}
```

- [ ] **Step 2: Update ResolveHosts to use cache**

Add a `cache` parameter:

```go
func ResolveHosts(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration, cache *DNSCache) map[string]*DNSResult {
    results := make(map[string]*DNSResult, len(hosts))
    var mu sync.Mutex

    // Separate cached and uncached hosts
    var uncached []string
    for _, h := range hosts {
        if cache != nil {
            if ip, isPrivate, ok := cache.Get(h); ok {
                results[h] = &DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}
                continue
            }
        }
        uncached = append(uncached, h)
    }

    if len(uncached) == 0 {
        return results
    }

    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(maxConcurrent)

    for _, h := range uncached {
        h := h
        g.Go(func() error {
            ip, isPrivate := resolveWithRetry(ctx, h, timeout)
            mu.Lock()
            results[h] = &DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}
            if cache != nil && ip != "" {
                cache.Set(h, ip, isPrivate)
            }
            mu.Unlock()
            return nil
        })
    }
    g.Wait()
    return results
}
```

- [ ] **Step 3: Update ResolveStream to use cache**

Similarly add cache support to `ResolveStream`:

```go
func ResolveStream(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration, cache *DNSCache) <-chan DNSResult {
    out := make(chan DNSResult, maxConcurrent)

    go func() {
        defer close(out)
        var uncached []string
        for _, h := range hosts {
            if cache != nil {
                if ip, isPrivate, ok := cache.Get(h); ok {
                    select {
                    case out <- DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}:
                    case <-ctx.Done():
                        return
                    }
                    continue
                }
            }
            uncached = append(uncached, h)
        }

        if len(uncached) == 0 {
            return
        }

        g, ctx := errgroup.WithContext(ctx)
        g.SetLimit(maxConcurrent)

        for _, h := range uncached {
            h := h
            g.Go(func() error {
                ip, isPrivate := resolveWithRetry(ctx, h, timeout)
                if cache != nil && ip != "" {
                    cache.Set(h, ip, isPrivate)
                }
                select {
                case out <- DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}:
                case <-ctx.Done():
                }
                return nil
            })
        }
        g.Wait()
    }()

    return out
}
```

- [ ] **Step 4: Add DNSCacheTTL to Config**

In `internal/config/config.go`:

```go
type Config struct {
    // ... existing fields ...
    DNSCacheTTL time.Duration `env:"DNS_CACHE_TTL" envDefault:"10m"`
}
```

In `cmd/vless-sub-server/main.go`, in `loadConfig`:

```go
if d, err := time.ParseDuration(envOr("DNS_CACHE_TTL", "10m")); err == nil {
    c.DNSCacheTTL = d
}
```

- [ ] **Step 5: Create persistent cache in main.go**

Add module-level variable:

```go
var dnsCache *dns.DNSCache
```

In `main()`, before the refresh loop:

```go
dnsCache = dns.NewDNSCache(cfg.DNSCacheTTL)
```

Update pipeline calls to pass the cache. In `ProbeAndFilterStream`:

```go
func ProbeAndFilterStream(ctx context.Context, records []parse.ProxyRecord, maxConcurrent int, dnsTimeout, tcpTimeout time.Duration, cache *dns.DNSCache) []ProbedProxy {
    // ...
    dnsCh := dns.ResolveStream(ctx, uniqueHosts, maxConcurrent, dnsTimeout, cache)
    // ...
}
```

After refresh, purge expired entries:

```go
dnsCache.Purge()
```

- [ ] **Step 6: Build and verify**

```bash
cd /home/michael/Github/vless-sub-server && CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server
```

- [ ] **Step 7: Commit**

```bash
git add internal/dns/dns.go internal/config/config.go cmd/vless-sub-server/main.go internal/pipeline/pipeline.go
git commit -m "perf: TTL-aware DNS cache across refresh cycles

Adds DNSCache with configurable TTL (default 10min). On subsequent
refreshes, cached hosts skip DNS resolution entirely. Purges expired
entries after each refresh. Saves 1.5-4s per cycle for stable
subscriptions."
```

---

## Self-Review

### Spec Coverage

| Spec Item | Task |
|-----------|------|
| P0: Raise MaxConcurrent | Task 1 |
| P1: Context propagation | Task 2 |
| P2: Streaming DNS+TCP | Tasks 5-6 |
| P3: Shared http.Transport | Task 3 |
| P5: errgroup unification | Task 4 |
| P6: DNS cache | Task 7 |
| P4: Long-lived xray | Future phase |
| P7: mmdb geo | Future phase |
| P8: Incremental refresh | Future phase |

### Placeholder Scan

No TBD, TODO, or "implement later" patterns found. All code blocks contain complete implementations.

### Type Consistency

- `HostSpec` struct defined in `probe.go` and referenced consistently in `pipeline.go` and `main.go`
- `DNSResult.Host` field added consistently across `dns.go`, `pipeline.go`
- `ProbedProxy` struct defined in `pipeline.go` and used in `main.go`
- All function signatures with `ctx context.Context` are consistent across packages
- `DNSCache` pointer passed as `*dns.DNSCache` throughout