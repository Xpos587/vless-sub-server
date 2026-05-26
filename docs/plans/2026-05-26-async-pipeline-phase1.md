# Async Pipeline Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate client-blocking refreshes, 5-10x DNS speedup via resolver racing + DoH, replace network geo API calls with offline GeoLite2 .mmdb lookup, and add pre-flight TCP check to skip dead proxies before expensive xray probe.

**Architecture:** Stale-while-revalidate: serve previous result instantly, trigger background refresh when stale. DNS: race system/miekg/DoH resolvers concurrently, take first success. Geo: local .mmdb files via oschwald/maxminddb-golang, inline lookup after exit IP obtained. TCP: 3s dial check filters dead hosts before xray probe.

**Tech Stack:** Go, oschwald/maxminddb-golang, net/http (DoH), miekg/dns, sync/atomic

---

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `internal/dns/dns.go` | Major modify | DNS resolver racing + DoH |
| `internal/geo/geo.go` | Major modify | Offline GeoLite2 .mmdb lookup, remove API calls |
| `internal/geo/geoip.go` | Create | GeoIPDB type + .mmdb init + auto-download |
| `internal/exitprobe/exitprobe.go` | Modify | Inline geo lookup, remove batchGeoLookup, add TCP pre-check |
| `internal/config/config.go` | Modify | Add GEO_DB_DIR, MAXMIND_LICENSE_KEY config |
| `cmd/vless-sub-server/main.go` | Modify | Stale-while-revalidate cache, GeoIPDB init |
| `Containerfile` | Modify | Add GeoLite2 .mmdb download stage |

---

## Task 1: Stale-While-Revalidate Cache (P0)

**Files:**

- Modify: `cmd/vless-sub-server/main.go`

**Context:** Currently singleflight blocks concurrent `/sub` requests during refresh. When cache is empty, 503 is returned. New behavior: serve stale data if available, trigger background refresh when stale. Only 503 on first-ever request if no data exists yet (with short wait).

- [ ] **Step 1: Add `refreshing` atomic flag and background refresh trigger**

In `cmd/vless-sub-server/main.go`, add after the `var` block (line 38):

```go
var refreshing atomic.Int32 // 0=idle, 1=refreshing
```

Add import `"sync/atomic"` if not already present.

- [ ] **Step 2: Replace singleflight-based refresh with `triggerRefresh`**

Replace the `refreshSF singleflight.Group` var and all usages. Remove import `"golang.org/x/sync/singleflight"`.

Replace `main()` goroutines:

```go
func main() {
	cfg = loadConfig()
	dnsCache = dns.NewDNSCache(cfg.DNSCacheTTL)

	os.Setenv("XRAY_LOCATION_ASSET", cfg.GeoDatDir)
	config.CustomHeaders["X-Hwid"] = cfg.Hwid

	port := cfg.Port
	refreshInterval := cfg.RefreshInterval

	log.Printf("[server] starting on :%d, refresh every %s", port, refreshInterval)

	triggerRefresh()

	ticker := time.NewTicker(refreshInterval)
	go func() {
		for range ticker.C {
			triggerRefresh()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleSub)
	mux.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[server] shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("[server] listening on :%d", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("[server] error: %v", err)
	}
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

- [ ] **Step 3: Update `handleSub` for stale-while-revalidate**

Replace `handleSub`:

```go
func handleSub(w http.ResponseWriter, r *http.Request) {
	v := cache.Load()
	if v == nil {
		// First request ever — trigger refresh and wait briefly
		triggerRefresh()
		select {
		case <-time.After(5 * time.Second):
			v = cache.Load()
		}
		if v == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("# initializing...\n"))
			return
		}
	}

	data := v.(*cachedData)
	// If stale, trigger background refresh but serve current data
	if time.Since(data.lastRefresh) > cfg.RefreshInterval {
		go triggerRefresh()
	}
	body := []byte(data.output)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Last-Refresh", data.lastRefresh.Format(time.RFC3339))
	w.Write(body)
}
```

- [ ] **Step 4: Remove singleflight import and var**

Remove `refreshSF singleflight.Group` from vars. Remove `"golang.org/x/sync/singleflight"` from imports.

- [ ] **Step 5: Build**

```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

Expected: compiles without errors.

- [ ] **Step 6: Commit**

```bash
git add cmd/vless-sub-server/main.go
git commit -m "feat: stale-while-revalidate cache — serve stale data, background refresh, no singleflight blocking"
```

---

## Task 2: DNS Resolver Racing + DoH (P1)

**Files:**

- Modify: `internal/dns/dns.go`
- Create: `internal/dns/racing.go`

**Context:** Current `resolveWithRetry` tries resolvers sequentially — worst case 5s(system) + 2s×3(miekg) + 200ms + retry = ~13s per host. Race all resolvers concurrently, take first success. Add DoH (DNS-over-HTTPS) racer to bypass port 53 blocking.

- [ ] **Step 1: Create `internal/dns/racing.go` with `resolveRacing` and `resolveDoH`**

```go
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type racerResult struct {
	ip  string
	priv bool
}

// resolveRacing races all DNS resolvers concurrently and returns the first success.
// Timeout is the max time for the entire race.
func resolveRacing(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return host, isPrivateIP(ip)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	first := make(chan racerResult, 1)
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
				case first <- racerResult{ip: ip, priv: isPrivateIPStr(ip)}:
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

// resolveMiekg resolves using miekg/dns with specific server and protocol.
func resolveMiekg(ctx context.Context, host, addr, network string) (string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = network
	c.Timeout = 2 * time.Second
	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return "", false
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), false
		}
	}
	return "", false
}

// resolveDoH resolves using DNS-over-HTTPS (RFC 8484 JSON API).
func resolveDoH(ctx context.Context, host, dohURL string) (string, bool) {
	u := fmt.Sprintf("%s?name=%s&type=A", dohURL, host)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return "", false
	}
	for _, a := range dohResp.Answer {
		if net.ParseIP(a.Data) != nil {
			return a.Data, false
		}
	}
	return "", false
}
```

- [ ] **Step 2: Replace `resolveWithRetry` in `internal/dns/dns.go` with `resolveRacing` call**

Replace `internal/dns/dns.go:108-132`:

```go
func resolveWithRetry(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	return resolveRacing(ctx, host, timeout)
}
```

- [ ] **Step 3: Remove old `resolveOne` function**

Delete `resolveOne` from `internal/dns/dns.go` (it's now `resolveMiekg` in racing.go). Remove `resolveSystem` too — it's now called from `resolveRacing`.

Actually, keep `resolveSystem` in dns.go since it's still used by `resolveRacing`. Only remove `resolveOne`.

Delete `internal/dns/dns.go:150-186` (the `resolveOne` function).

- [ ] **Step 4: Build**

```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

Expected: compiles without errors. `"time"` import may be unused in dns.go now — remove if so.

- [ ] **Step 5: Smoke test**

```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VY08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[dns\]" | head -10
```

Expected: DNS resolution significantly faster. Previously sequential ~2s per host, now racing ~200ms per host.

- [ ] **Step 6: Commit**

```bash
git add internal/dns/dns.go internal/dns/racing.go
git commit -m "feat: DNS resolver racing — race system/miekg/DoH concurrently, 5-10x speedup"
```

---

## Task 3: Offline GeoLite2 .mmdb Lookup (P1)

**Files:**

- Create: `internal/geo/geoip.go`
- Modify: `internal/geo/geo.go`
- Modify: `internal/exitprobe/exitprobe.go`
- Modify: `cmd/vless-sub-server/main.go`
- Modify: `internal/config/config.go`
- Modify: `Containerfile`

**Context:** Current geo lookups: ip-api.com batch HTTP call (10s timeout, rate-limited) + ipwho.is per-proxy during exit probing. Replace with local .mmdb files — ~1-5μs per lookup, zero network dependency.

- [ ] **Step 1: Add `maxminddb-golang` dependency**

```bash
go get github.com/oschwald/maxminddb-golang
```

- [ ] **Step 2: Add config fields**

In `internal/config/config.go`, add to `Config` struct:

```go
GeoDBDir          string        `env:"GEO_DB_DIR" envDefault:"/usr/local/share/xray"`
MaxMindLicenseKey string        `env:"MAXMIND_LICENSE_KEY"`
```

Rename `GeoDatDir` to `GeoDBDir` (both xray geo dat and mmdb files live in the same dir). Update `main.go` reference.

Actually, keep `GeoDatDir` for xray and add new field:

```go
GeoDBDir          string        `env:"GEO_DB_DIR" envDefault:"/usr/local/share/xray"`
```

Add to `loadConfig()` in `main.go`:

```go
c.GeoDBDir = envOr("GEO_DB_DIR", "/usr/local/share/xray")
```

- [ ] **Step 3: Create `internal/geo/geoip.go`**

```go
package geo

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type GeoIPDB struct {
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
	mu     sync.RWMutex
}

// NewGeoIPDB loads GeoLite2 City and ASN .mmdb files from dir.
// Returns nil if files not found (caller should fall back to API).
func NewGeoIPDB(dir string) *GeoIPDB {
	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")

	cityDB, err := maxminddb.Open(cityPath)
	if err != nil {
		log.Printf("[geoip] city db not found: %s (%v)", cityPath, err)
		return nil
	}

	asnDB, err := maxminddb.Open(asnPath)
	if err != nil {
		log.Printf("[geoip] asn db not found: %s (%v)", asnPath, err)
		cityDB.Close()
		return nil
	}

	log.Printf("[geoip] loaded GeoLite2 City+ASN from %s", dir)
	return &GeoIPDB{cityDB: cityDB, asnDB: asnDB}
}

func (db *GeoIPDB) Close() {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.cityDB != nil {
		db.cityDB.Close()
		db.cityDB = nil
	}
	if db.asnDB != nil {
		db.asnDB.Close()
		db.asnDB = nil
	}
}

// Lookup returns GeoInfo for an IP using local .mmdb databases.
// Returns nil if IP not found.
func (db *GeoIPDB) Lookup(ipStr string) *GeoInfo {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.cityDB == nil {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	var city struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	if err := db.cityDB.Lookup(ip, &city); err != nil {
		return nil
	}
	if city.Country.ISOCode == "" {
		return nil
	}

	isp := ""
	if db.asnDB != nil {
		var asn struct {
			AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		}
		if err := db.asnDB.Lookup(ip, &asn); err == nil {
			isp = asn.AutonomousSystemOrganization
		}
	}

	cityName := city.City.Names["en"]
	if cityName == "" {
		cityName = city.Country.ISOCode
	}
	if isp == "" {
		isp = "Unknown"
	}

	return &GeoInfo{
		CountryCode: city.Country.ISOCode,
		City:        cityName,
		ISP:         isp,
		IP:          ipStr,
	}
}

// AutoDownload downloads GeoLite2 databases if they don't exist.
// Requires MAXMIND_LICENSE_KEY env var.
func AutoDownload(dir, licenseKey string) error {
	if licenseKey == "" {
		return fmt.Errorf("MAXMIND_LICENSE_KEY not set")
	}

	cityPath := filepath.Join(dir, "GeoLite2-City.mmdb")
	asnPath := filepath.Join(dir, "GeoLite2-ASN.mmdb")

	if fileExists(cityPath) && fileExists(asnPath) {
		return nil // already downloaded
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	baseURL := fmt.Sprintf("https://download.maxmind.com/app/geoip_download?license_key=%s&edition_id=", licenseKey)

	if !fileExists(cityPath) {
		url := baseURL + "GeoLite2-City&suffix=tar.gz"
		log.Printf("[geoip] downloading GeoLite2-City...")
		if err := downloadAndExtract(url, dir, "GeoLite2-City.mmdb"); err != nil {
			return fmt.Errorf("download city db: %w", err)
		}
	}

	if !fileExists(asnPath) {
		url := baseURL + "GeoLite2-ASN&suffix=tar.gz"
		log.Printf("[geoip] downloading GeoLite2-ASN...")
		if err := downloadAndExtract(url, dir, "GeoLite2-ASN.mmdb"); err != nil {
			return fmt.Errorf("download asn db: %w", err)
		}
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
```

- [ ] **Step 4: Create `internal/geo/download.go` for auto-download helper**

```go
package geo

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func downloadAndExtract(url, dir, targetFile string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		// Find the .mmdb file inside the tar (nested in edition-id/date/ dir)
		if hdr.Typeflag == tar.TypeReg && strings.HasSuffix(hdr.Name, targetFile) {
			outPath := filepath.Join(dir, targetFile)
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("create %s: %w", outPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			f.Close()
			log.Printf("[geoip] extracted %s (%d bytes)", targetFile, hdr.Size)
			return nil
		}
	}

	return fmt.Errorf("%s not found in archive", targetFile)
}
```

Wait, `log` is not imported. Add `"log"` to imports in download.go.

- [ ] **Step 5: Remove `BatchGeoLookup` and `GeoInfoFromExitIP` from `internal/geo/geo.go`**

These are replaced by `GeoIPDB.Lookup()`. Remove `BatchGeoLookup` and `GeoInfoFromExitIP` functions. Remove `"bytes"`, `"fmt"`, `"io"`, `"net/http"`, `"time"` imports from geo.go. Keep `GeoInfo`, `IPWhoisResponse`, `CFTraceResult`, `IPAPIEntry` types for now (exitprobe still uses IPWhoisResponse).

Actually, `IPWhoisResponse` is used by `exitprobe.probeSingle` to parse ipwho.is response. Keep it. But `BatchGeoLookup` and `GeoInfoFromExitIP` are no longer needed.

After removal, `internal/geo/geo.go` becomes:

```go
package geo

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

type IPWhoisResponse struct {
	IP          string `json:"ip"`
	Success     bool   `json:"success"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Connection  struct {
		ISP string `json:"isp"`
	} `json:"connection"`
}
```

- [ ] **Step 6: Add `GeoIPDB` to `ExitProber` and inline geo lookup in `probeSingle`**

In `internal/exitprobe/exitprobe.go`, add to `ExitProber` struct:

```go
type ExitProber struct {
	cfg       *config.Config
	instance  *core.Instance
	proxyTags []string
	transport *http.Transport
	geoDB     *geo.GeoIPDB
	mu        sync.Mutex
}
```

Update `NewExitProber`:

```go
func NewExitProber(cfg *config.Config, geoDB *geo.GeoIPDB) *ExitProber {
	return &ExitProber{
		cfg:    cfg,
		geoDB:  geoDB,
		transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			DialContext:           (&net.Dialer{Timeout: cfg.ExitProbeTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   cfg.ExitProbeTimeout,
			ResponseHeaderTimeout:  cfg.ExitProbeTimeout,
		},
	}
}
```

- [ ] **Step 7: Update `probeSingle` to use inline geo lookup**

Replace geo lookup section at end of `probeSingle`:

```go
	var ipResp geo.IPWhoisResponse
	if err := json.Unmarshal(body, &ipResp); err != nil || !ipResp.Success {
		return ep.probeCFTrace(ctx, transport)
	}

	result := &ExitProbeResult{
		ExitIP:  ipResp.IP,
		ExitLoc: ipResp.CountryCode,
		XrayOK:  true,
	}

	// Inline geo lookup: .mmdb first, then ipwho.is data
	if ep.geoDB != nil {
		result.GeoInfo = ep.geoDB.Lookup(ipResp.IP)
	}
	if result.GeoInfo == nil {
		result.GeoInfo = &geo.GeoInfo{
			CountryCode: ipResp.CountryCode,
			City:        ipResp.City,
			ISP:         ipResp.Connection.ISP,
			IP:          ipResp.IP,
		}
	}

	return result
```

- [ ] **Step 8: Update `probeCFTrace` to use inline geo lookup**

At end of `probeCFTrace`, add mmdb lookup:

```go
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

	// Inline geo lookup from .mmdb
	if ep.geoDB != nil {
		result.GeoInfo = ep.geoDB.Lookup(result.ExitIP)
	}
	if result.GeoInfo == nil && result.ExitLoc != "" {
		result.GeoInfo = &geo.GeoInfo{
			CountryCode: result.ExitLoc,
			City:        result.ExitLoc,
			ISP:         "Unknown",
			IP:          result.ExitIP,
		}
	}

	return result
```

- [ ] **Step 9: Remove `batchGeoLookup` from `exitprobe.go`**

Delete the `batchGeoLookup` method entirely. Remove the call in `ProbeAll`:

```go
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
			return nil
		})
	}
	g.Wait()

	return results
}
```

Remove `"bytes"`, `"encoding/json"` imports if no longer used (json still used for ipwho.is parse, keep it). Remove `"net/http"` if no longer used directly (still used for probeSingle transport). Actually keep most imports, just remove `"bytes"`.

Wait, `bytes` is used in `StartWithProxies` for `bytes.NewReader(configJSON)`. Keep it.

- [ ] **Step 10: Update `main.go` to init GeoIPDB and pass to ExitProber**

In `main()`, after `loadConfig()`:

```go
	var geoDB *geo.GeoIPDB
	if cfg.MaxMindLicenseKey != "" {
		if err := geo.AutoDownload(cfg.GeoDBDir, cfg.MaxMindLicenseKey); err != nil {
			log.Printf("[geoip] auto-download failed: %v", err)
		}
	}
	geoDB = geo.NewGeoIPDB(cfg.GeoDBDir)
```

In `refreshSubscriptions`, replace:

```go
ep := exitprobe.NewExitProber(cfg)
```

with:

```go
ep := exitprobe.NewExitProber(cfg, geoDB)
```

- [ ] **Step 11: Update Containerfile to download GeoLite2**

Add a new stage in `Containerfile` to download .mmdb files:

After the `geo-builder` stage, add:

```dockerfile
# Stage 3.5: Download GeoLite2 databases (optional, needs MAXMIND_LICENSE_KEY at build time)
# If no license key, mmdb files can be mounted at runtime via volume
FROM docker.io/library/alpine:3.21 AS mmdb-builder
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      apk add --no-cache curl && \
      mkdir -p /tmp/geoip && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-City&suffix=tar.gz" -o /tmp/city.tar.gz && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" -o /tmp/asn.tar.gz && \
      cd /tmp && \
      tar xzf city.tar.gz --strip-components=1 --include='*.mmdb' -C /tmp/geoip 2>/dev/null || true && \
      tar xzf asn.tar.gz --strip-components=1 --include='*.mmdb' -C /tmp/geoip 2>/dev/null || true; \
    else \
      mkdir -p /tmp/geoip; \
    fi
```

In the runtime stage, add COPY:

```dockerfile
COPY --from=mmdb-builder /tmp/geoip/*.mmdb /usr/local/share/xray/
```

Note: The `--strip-components` with `--include` may not work on all tar versions. Alternative: use a shell script to find and copy the .mmdb files from the extracted directory tree. Let me simplify:

```dockerfile
# Stage 3.5: Download GeoLite2 databases
FROM docker.io/library/alpine:3.21 AS mmdb-builder
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      apk add --no-cache curl && \
      mkdir -p /tmp/geoip && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-City&suffix=tar.gz" | \
        tar xz --strip-components=0 -C /tmp/geoip --wildcards '*/GeoLite2-City.mmdb' 2>/dev/null || true && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" | \
        tar xz --strip-components=0 -C /tmp/geoip --wildcards '*/GeoLite2-ASN.mmdb' 2>/dev/null || true && \
      find /tmp/geoip -name '*.mmdb' -exec mv {} /tmp/geoip/ \; && \
      rm -f /tmp/geoip/*.tar.gz; \
    else \
      mkdir -p /tmp/geoip; \
    fi
```

Actually Alpine's tar may not support `--wildcards`. Simpler approach:

```dockerfile
FROM docker.io/library/alpine:3.21 AS mmdb-builder
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      apk add --no-cache curl && \
      mkdir -p /tmp/geoip && \
      cd /tmp/geoip && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-City&suffix=tar.gz" | tar xz && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" | tar xz && \
      find /tmp/geoip -name 'GeoLite2-City.mmdb' -exec mv {} /tmp/geoip/ \; && \
      find /tmp/geoip -name 'GeoLite2-ASN.mmdb' -exec mv {} /tmp/geoip/ \; && \
      rm -rf /tmp/geoip/GeoLite2-*; \
    else \
      mkdir -p /tmp/geoip; \
    fi
```

Wait, `rm -rf /tmp/geoip/GeoLite2-*` would also delete the .mmdb files. Fix:

```dockerfile
FROM docker.io/library/alpine:3.21 AS mmdb-builder
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      apk add --no-cache curl && \
      mkdir -p /tmp/geoip && \
      cd /tmp/geoip && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-City&suffix=tar.gz" | tar xz && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" | tar xz && \
      find /tmp/geoip -name 'GeoLite2-City.mmdb' -exec mv {} /tmp/geoip/GeoLite2-City.mmdb \; && \
      find /tmp/geoip -name 'GeoLite2-ASN.mmdb' -exec mv {} /tmp/geoip/GeoLite2-ASN.mmdb \; && \
      rm -rf /tmp/geoip/GeoLite2-*/; \
    else \
      mkdir -p /tmp/geoip; \
    fi
```

- [ ] **Step 12: Build**

```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

Expected: compiles. May need to fix import issues if `geo.GeoIPDB` not found.

- [ ] **Step 13: Test with .mmdb files (if available) or without (fallback)**

```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VY08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[geoip\]" | head -10
```

Expected: if .mmdb files found → `[geoip] loaded GeoLite2 City+ASN`. If not found → `[geoip] city db not found` + falls back to ipwho.is data. Either way, geo data should be present.

- [ ] **Step 14: Commit**

```bash
git add internal/geo/geoip.go internal/geo/geo.go internal/geo/download.go internal/exitprobe/exitprobe.go cmd/vless-sub-server/main.go internal/config/config.go Containerfile go.mod go.sum
git commit -m "feat: offline GeoLite2 .mmdb lookup — replace ip-api.com + ipwho.is geo calls with local database"
```

---

## Task 4: Pre-Flight TCP Check Before Xray Probe (P2)

**Files:**

- Modify: `internal/exitprobe/exitprobe.go`

**Context:** Skip xray probe for hosts that fail TCP connection test. TCP check is ~100ms, xray probe is ~12s. Filtering 30-50% of dead proxies before the expensive xray phase saves significant time.

- [ ] **Step 1: Add `tcpReachable` function**

Add to `internal/exitprobe/exitprobe.go`:

```go
func tcpReachable(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		addr = fmt.Sprintf("[%s]:%d", host, port)
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
```

- [ ] **Step 2: Add TCP check in `probeSingle`**

At the beginning of `probeSingle`, after the context check:

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

	// Pre-flight TCP check — skip expensive xray probe if host unreachable
	if !tcpReachable(record.Host, record.Port, 3*time.Second) {
		return &ExitProbeResult{XrayOK: false}
	}

	// ... rest of probeSingle
```

- [ ] **Step 3: Build**

```bash
CGO_ENABLED=0 go build -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

- [ ] **Step 4: Smoke test**

```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VY08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]" | head -5
```

Expected: faster overall refresh (dead proxies skipped in ~3s instead of ~12s). Alive count should be same or slightly lower (dead hosts correctly filtered).

- [ ] **Step 5: Commit**

```bash
git add internal/exitprobe/exitprobe.go
git commit -m "feat: pre-flight TCP check before xray probe — skip unreachable hosts in ~100ms vs ~12s"
```

---

## Task 5: Final Integration Test

**Files:**

- All modified files

**Context:** Verify all P0-P2 changes work together. Run full pipeline, verify stale-while-revalidate, DNS racing, offline geo, TCP pre-check.

- [ ] **Step 1: Full build**

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o vless-sub-server ./cmd/vless-sub-server && echo "BUILD OK"
```

- [ ] **Step 2: Run with real subscriptions**

```bash
SUBSCRIPTION_URLS="https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VY08Uu9T30aTE" HWID=cb46d5c2545131323baa5a7d67cb05c6 timeout 60 ./vless-sub-server 2>&1 | grep -E "\[refresh\]|\[server\]|\[geoip\]|\[dns\]" | head -15
```

Verify:
- `[geoip] loaded GeoLite2 City+ASN` OR `[geoip] city db not found` (graceful fallback)
- `[refresh] done in Xs` — should be faster than pre-optimization
- No crashes, no resource leaks

- [ ] **Step 3: Test stale-while-revalidate**

While server running, after first refresh completes:
1. Hit `/sub` → instant response with `X-Last-Refresh` header
2. Wait for stale period, hit `/sub` again → should still return instantly with old data while background refresh runs

```bash
curl -s -D - http://localhost:8080/sub | head -10
```

- [ ] **Step 4: Test `/sub` and `/health`**

```bash
curl -s http://localhost:8080/health
```

Expected: `ok`

- [ ] **Step 5: Run unit tests**

```bash
go test ./... 2>&1
```

Expected: all tests pass.

- [ ] **Step 6: Build container**

```bash
podman build --no-cache -t docker.io/xpos587/vless-sub-server:latest . 2>&1 | tail -5
```

Expected: successful build.

- [ ] **Step 7: Final commit if any remaining changes**

```bash
git status
# Only commit if there are uncommitted changes
git add -A
git commit -m "chore: async pipeline Phase 1 complete — stale-while-revalidate, DNS racing, offline GeoIP, TCP pre-check"
```

---

## Self-Review

### Spec Coverage

| Spec Item | Task |
|-----------|------|
| P0: Stale-while-revalidate | Task 1 |
| P1: DNS resolver racing + DoH | Task 2 |
| P1: Offline GeoLite2 | Task 3 |
| P2: Pre-flight TCP check | Task 4 |
| Integration | Task 5 |
| P2: Channel-based pipeline | Phase 2 (not this plan) |
| P3: Incremental refresh | Phase 2 (not this plan) |

### Placeholder Scan

No TBD, TODO, or placeholder patterns. All steps contain complete code.

### Type Consistency

- `GeoIPDB` — created in `geo/geoip.go`, passed to `NewExitProber` — consistent
- `ExitProber.geoDB` field — `*geo.GeoIPDB` — matches `NewGeoIPDB` return type
- `cachedData` — unchanged from current code — consistent
- `racerResult` — internal to `racing.go` — consistent
- `Config.GeoDBDir` — string, used by `NewGeoIPDB(dir)` — consistent
