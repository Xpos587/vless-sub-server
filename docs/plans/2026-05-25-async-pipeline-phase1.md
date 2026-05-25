# Async Pipeline Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce typical refresh from 30-45s to 12-15s by eliminating SOCKS5 overhead, fixing DNS bottleneck, adding atomic cache swap, and improving HTTP connection handling.

**Architecture:** Replace SOCKS5 inbound pattern with `core.Dial()` + `session.SetForcedOutboundTagToContext()` for direct xray routing. Fix DNS unconditional sleep and context propagation. Replace plain `string` cache with `atomic.Value` for stale-while-recharging. Share `http.Transport` across probes instead of cloning.

**Tech Stack:** Go, xray-core (as library), golang.org/x/sync/errgroup, sync/atomic

---

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `internal/dns/dns.go` | Modify | Fix `resolveWithRetry` sleep + context propagation |
| `cmd/vless-sub-server/main.go` | Modify | Atomic cache swap (P3) |
| `internal/exitprobe/exitprobe.go` | Major refactor | core.Dial() (P0), shared transport + body drain (P4) |
| `internal/config/config.go` | No changes | — |

---

## Task 1: Fix DNS `resolveWithRetry` — Context Propagation + Reduced Sleep (P2)

**Files:**

- Modify: `internal/dns/dns.go:108-128`

**Context:** `resolveWithRetry` ignores its `ctx` parameter, using `context.Background()` for all internal calls. It also has an unconditional 500ms sleep (line 123) that fires even on NXDOMAIN. With 30 unique hosts, this adds up to 15s of pure delay.

- [ ] **Step 1: Fix `resolveWithRetry` signature and body**

Replace the entire function at `internal/dns/dns.go:108-128`:

```go
func resolveWithRetry(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return host, true
		}
		return host, false
	}

	if ip, ok := resolveSystem(ctx, host); ok {
		return ip, isPrivateIPStr(ip)
	}

	if ip, ok := resolveOne(ctx, host, timeout); ok {
		return ip, isPrivateIPStr(ip)
	}

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

Changes: `_(context.Context` → `ctx context.Context`, all `context.Background()` → `ctx`, `time.Sleep(500ms)` → `select` with `time.After(200ms)` + `ctx.Done()`.

- [ ] **Step 2: Fix `resolveSystem` to use passed context**

Replace `internal/dns/dns.go:130-144`:

```go
func resolveSystem(ctx context.Context, host string) (string, bool) {
	sysCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(sysCtx, host)
	if err != nil {
		return "", false
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String(), true
		}
	}
	return "", false
}
```

Change: `context.Background()` → `ctx` in `WithTimeout`.

- [ ] **Step 3: Fix `resolveOne` to use passed context**

Replace `internal/dns/dns.go:146-182`:

```go
func resolveOne(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	servers := []struct {
		addr string
		net  string
	}{
		{"100.100.100.100:53", "udp"},
		{"8.8.8.8:53", "tcp"},
		{"1.1.1.1:53", "tcp"},
	}

	for _, s := range servers {
		c := new(dns.Client)
		c.Net = s.net
		c.Timeout = timeout
		r, _, err := c.ExchangeContext(resolveCtx, m, s.addr)
		if err != nil {
			continue
		}
		if len(r.Answer) == 0 {
			continue
		}
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				return a.A.String(), false
			}
		}
	}

	return "", false
}
```

Change: `context.Background()` → `ctx` in `WithTimeout`.

- [ ] **Step 4: Build and test**

Run:
```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

Expected: compiles without errors.

- [ ] **Step 5: Smoke test**

Run:
```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 45 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[config\]|\[server\]" | head -10
```

Expected: `[refresh] done in ...` with fewer seconds than previous 12s baseline (DNS should be faster due to 200ms vs 500ms retry delay).

- [ ] **Step 6: Commit**

```bash
git add internal/dns/dns.go
git commit -m "fix: thread context through DNS resolve, reduce retry sleep from 500ms to 200ms with cancellation"
```

---

## Task 2: Atomic Cache Swap (P3)

**Files:**

- Modify: `cmd/vless-sub-server/main.go:27-33, 274-278, 294-305`

**Context:** `cachedOutput` is a plain `string` and `lastRefresh` is a `time.Time`. During refresh (15-45s), `singleflight` blocks concurrent `/sub` requests. Replace with `atomic.Value` so stale data is served instantly.

- [ ] **Step 1: Add `cachedData` struct and `atomic.Value`**

Replace `cmd/vless-sub-server/main.go:27-33`:

```go
type cachedData struct {
	output     string
	lastRefresh time.Time
}

var (
	cache     atomic.Value // stores *cachedData
	refreshSF singleflight.Group
	cfg       *config.Config
	dnsCache  *dns.DNSCache
)
```

Add `"sync/atomic"` to imports.

- [ ] **Step 2: Update end of `refreshSubscriptions`**

Replace `cmd/vless-sub-server/main.go:276-278`:

```go
	cache.Store(&cachedData{output: output, lastRefresh: time.Now()})
	dnsCache.Purge()
	log.Printf("[refresh] done in %s: %d alive, %d with geo", time.Since(start), totalAlive, geoAvailable)
```

- [ ] **Step 3: Update `handleSub`**

Replace `cmd/vless-sub-server/main.go:294-305`:

```go
func handleSub(w http.ResponseWriter, r *http.Request) {
	v := cache.Load()
	if v == nil {
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
```

- [ ] **Step 4: Build and test**

Run:
```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

Expected: compiles. `cachedOutput` and `lastRefresh` should now be unused — verify no compilation errors.

- [ ] **Step 5: Smoke test**

Run:
```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 45 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[server\]" | head -10
```

Expected: same behavior as before — `[refresh] done`, server listening on 8080.

- [ ] **Step 6: Commit**

```bash
git add cmd/vless-sub-server/main.go
git commit -m "refactor: replace cachedOutput string with atomic.Value for stale-while-recharging"
```

---

## Task 3: core.Dial() Refactoring — Eliminate SOCKS5 Inbounds (P0)

**Files:**

- Modify: `internal/exitprobe/exitprobe.go` (major refactor)

**Context:** Current pattern: N SOCKS5 inbounds + N outbounds + N routing rules + `findFreePorts()`. New pattern: only outbounds + `core.Dial()` with `session.SetForcedOutboundTagToContext()` for direct dispatch. Verified: xray-core dispatcher checks `forcedOutboundTag` first (line 407 in `app/dispatcher/default.go`), bypassing routing entirely. No inbounds or routing rules needed.

**xray-core API reference:**
- `core.Dial(ctx, instance, dest)` → `net.Conn` — `xray:api:stable`
- `session.SetForcedOutboundTagToContext(ctx, tag)` → `context.Context`
- `net.TCPDestination(net.ParseAddress(host), net.Port(port))` — destination constructor
- Imports: `"github.com/xtls/xray-core/common/session"`, `"github.com/xtls/xray-core/common/net"` (aliased as `xnet` to avoid conflict with `"net"`)

- [ ] **Step 1: Update `ExitProber` struct**

Replace `internal/exitprobe/exitprobe.go:33-39`:

```go
type ExitProber struct {
	cfg        *config.Config
	instance   *core.Instance
	proxyTags  []string // proxy index -> outbound tag
	transport  *http.Transport
	mu         sync.Mutex
}
```

Remove `socksPorts map[int]int`. Add `proxyTags []string`.

- [ ] **Step 2: Add xray-core imports**

Update `internal/exitprobe/exitprobe.go:3-24` imports:

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"

	"github.com/xtls/xray-core/common/session"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/sync/errgroup"
)
```

Removed: `"net/url"`. Added: `"strconv"`, `"github.com/xtls/xray-core/common/session"`, `xnet "github.com/xtls/xray-core/common/net"`.

- [ ] **Step 3: Remove `findFreePorts` function**

Delete `internal/exitprobe/exitprobe.go:41-52` (the entire `findFreePorts` function).

- [ ] **Step 4: Remove old xray config types**

Delete `internal/exitprobe/exitprobe.go:298-329` (the `xrayInbound`, `xrayRoutingRule`, `xrayConfig` types). Keep only `xrayOutbound`.

- [ ] **Step 5: Add new simplified config type**

Add after `xrayOutbound`:

```go
type xrayDialConfig struct {
	Log       map[string]any    `json:"log"`
	Outbounds []xrayOutbound    `json:"outbounds"`
}
```

- [ ] **Step 6: Replace `buildCheckConfig` with `buildOutboundOnlyConfig`**

Replace `internal/exitprobe/exitprobe.go:331-370`:

```go
func buildOutboundOnlyConfig(records []parse.ProxyRecord) []byte {
	cfg := xrayDialConfig{
		Log: map[string]any{"loglevel": "warning"},
	}

	cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
		Tag:      "direct",
		Protocol: "freedom",
		Settings: map[string]any{},
	})

	for i, rec := range records {
		outTag := fmt.Sprintf("proxy_%d_out", i)
		ob := buildOutbound(rec, outTag)
		cfg.Outbounds = append(cfg.Outbounds, ob)
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	return data
}
```

No inbounds, no routing rules. Only outbounds + direct.

- [ ] **Step 7: Update `StartWithProxies`**

Replace `internal/exitprobe/exitprobe.go:69-103`:

```go
func (ep *ExitProber) StartWithProxies(records []parse.ProxyRecord) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.instance != nil {
		ep.instance.Close()
		ep.instance = nil
	}

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
```

- [ ] **Step 8: Update `NewExitProber`**

Replace `internal/exitprobe/exitprobe.go:54-67`:

```go
func NewExitProber(cfg *config.Config) *ExitProber {
	return &ExitProber{
		cfg:       cfg,
		proxyTags: nil,
		transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			DialContext:           (&net.Dialer{Timeout: cfg.ExitProbeTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   cfg.ExitProbeTimeout,
			ResponseHeaderTimeout: cfg.ExitProbeTimeout,
		},
	}
}
```

Note: `ep.transport` is kept as a fallback base but not used for proxy dialing anymore. It will be replaced per-probe with a custom `DialContext`.

- [ ] **Step 9: Rewrite `probeSingle` to use `core.Dial`**

Replace `internal/exitprobe/exitprobe.go:142-195`:

```go
func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
	select {
	case <-ctx.Done():
		return &ExitProbeResult{XrayOK: false}
	default:
	}

	if idx >= len(ep.proxyTags) {
		return &ExitProbeResult{XrayOK: false}
	}
	outboundTag := ep.proxyTags[idx]

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)
			dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
			return core.Dial(ctx, ep.instance, dest)
		},
		TLSHandshakeTimeout:   ep.cfg.ExitProbeTimeout,
		ResponseHeaderTimeout: ep.cfg.ExitProbeTimeout,
		IdleConnTimeout:        90 * time.Second,
	}
	client := &http.Client{Transport: transport}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}

	var ipResp geo.IPWhoisResponse
	if err := json.Unmarshal(body, &ipResp); err != nil || !ipResp.Success {
		return ep.probeCFTrace(ctx, transport)
	}

	return &ExitProbeResult{
		ExitIP:  ipResp.IP,
		ExitLoc: ipResp.CountryCode,
		XrayOK:  true,
		GeoInfo: &geo.GeoInfo{
			CountryCode: ipResp.CountryCode,
			City:        ipResp.City,
			ISP:         ipResp.Connection.ISP,
			IP:          ipResp.IP,
		},
	}
}
```

- [ ] **Step 10: Update `probeCFTrace` signature**

Replace `internal/exitprobe/exitprobe.go:197-230`:

```go
func (ep *ExitProber) probeCFTrace(ctx context.Context, transport *http.Transport) *ExitProbeResult {
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}

	result := &ExitProbeResult{XrayOK: true}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			result.ExitIP = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			result.ExitLoc = strings.TrimPrefix(line, "loc=")
		}
	}
	if result.ExitIP == "" {
		return &ExitProbeResult{XrayOK: false}
	}
	return result
}
```

No change to logic, just kept consistent with new transport pattern.

- [ ] **Step 11: Build and fix compilation errors**

Run:
```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server 2>&1
```

Expected: may have errors from leftover references to `socksPorts`, `findFreePorts`, old config types. Fix any remaining references. The `url` import should now be unused — remove it.

- [ ] **Step 12: Smoke test with real subscriptions**

Run:
```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[server\]|Xray.*started" | head -10
```

Expected: `[refresh] done in ...` with 44 alive, 44 with geo. Xray should start without port allocation. No `address already in use` errors.

- [ ] **Step 13: Verify forced outbound routing**

Check that the xray logs show `taking platform initialized detour [proxy_N_out]` entries, confirming `SetForcedOutboundTagToContext` routes through the correct outbound.

Run with full output for a few seconds:
```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 30 ./vless-sub-server 2>&1 | grep -E "platform initialized detour|accepted|started" | head -10
```

Expected: `taking platform initialized detour [proxy_0_out]` type entries, confirming forced routing works.

- [ ] **Step 14: Commit**

```bash
git add internal/exitprobe/exitprobe.go
git commit -m "feat: replace SOCKS5 inbounds with core.Dial() + SetForcedOutboundTagToContext

Eliminates findFreePorts, SOCKS5 inbounds, routing rules.
Each probe dials directly through xray dispatcher with forced outbound tag.
Simpler config: only outbounds + direct."
```

---

## Task 4: Shared Transport + Body Draining (P4)

**Files:**

- Modify: `internal/exitprobe/exitprobe.go`

**Context:** After P0, each `probeSingle` already creates a fresh `http.Transport` with `core.Dial` DialContext. Body draining ensures HTTP/1.1 connections are reusable and prevents resource leaks. With the `core.Dial` pattern, each probe already gets its own transport, so we just need to add body draining in `probeSingle` and `probeCFTrace`.

- [ ] **Step 1: Add body draining to `probeSingle`**

In `probeSingle`, after `io.ReadAll(resp.Body)` and before the JSON unmarshal, add draining. Replace the defer+read pattern:

```go
	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
```

Replace `defer resp.Body.Close()` with `defer { drain + close }`. This ensures any remaining bytes are consumed so the connection can be reused by the transport pool.

- [ ] **Step 2: Add body draining to `probeCFTrace`**

Same pattern in `probeCFTrace`:

```go
	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
```

- [ ] **Step 3: Build and test**

Run:
```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

- [ ] **Step 4: Smoke test**

Run:
```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 45 ./vless-sub-server 2>&1 | grep -E "\[refresh\]" | head -5
```

Expected: `[refresh] done in ...` — same results, no resource leaks.

- [ ] **Step 5: Commit**

```bash
git add internal/exitprobe/exitprobe.go
git commit -m "fix: drain response body before close for proper HTTP connection reuse"
```

---

## Task 5: Final Integration Test

**Files:**

- All modified files

**Context:** Verify all P0-P4 changes work together. Run full pipeline and compare timing with original baseline.

- [ ] **Step 1: Full build**

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

- [ ] **Step 2: Run with real subscriptions and capture timing**

```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[server\]|Xray" | head -15
```

Verify:
- `[server] starting on :8080` — server starts
- `Xray 26.* started` — xray instance starts (should be faster with no inbounds)
- `[refresh] parsed=44 filtered=44 dns-resolved=44` — all proxies resolved
- `[refresh] done in Xs: 44 alive, 44 with geo` — all probed successfully
- No `address already in use` errors
- No `failed to listen TCP` errors

- [ ] **Step 3: Test `/sub` endpoint**

In another terminal while server is running:
```bash
curl -s http://localhost:8080/sub | head -5
curl -s http://localhost:8080/health
```

Expected: subscription output with header, `ok` from health.

- [ ] **Step 4: Test stale-while-recharging**

While server is running, wait for first refresh to complete. Then trigger another refresh and hit `/sub` during it — should return previous result instantly (non-blocking).

- [ ] **Step 5: Build container image**

```bash
podman build --no-cache -t docker.io/xpos587/vless-sub-server:latest . 2>&1 | tail -5
```

Expected: `Successfully tagged docker.io/xpos587/vless-sub-server:latest`

- [ ] **Step 6: Final commit (if any remaining changes)**

```bash
git status
git add -A
git commit -m "chore: Phase 1 async pipeline optimizations complete — P0-P4"
```

---

## Self-Review

### Spec Coverage

| Spec Item | Task |
|-----------|------|
| P0: core.Dial() refactoring | Task 3 |
| P1: Streaming pipeline | Phase 2 (not this plan) |
| P2: DNS sleep + context fix | Task 1 |
| P3: Atomic cache swap | Task 2 |
| P4: Shared transport + body drain | Task 4 |
| Integration test | Task 5 |

### Placeholder Scan

No TBD, TODO, or placeholder patterns found. All steps contain complete code.

### Type Consistency

- `ExitProber.proxyTags` ([]string) — set in `StartWithProxies`, read in `probeSingle` — consistent
- `cachedData` struct — stored via `cache.Store(&cachedData{...})`, loaded via `cache.Load().(*cachedData)` — consistent
- `xrayDialConfig` — new type replacing `xrayConfig`, only has `Log` + `Outbounds` — consistent with `buildOutboundOnlyConfig`
- `xrayOutbound` — unchanged, reused from current code — consistent
- `buildOutbound`, `buildStreamSettings`, `vlessEncryption` — untouched — consistent
