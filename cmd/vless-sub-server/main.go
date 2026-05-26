package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

const initWaitTimeout = 5 * time.Second

type cachedData struct {
	output      string
	lastRefresh time.Time
}

var (
	cache      atomic.Value   // stores *cachedData
	refreshing atomic.Int32   // 0=idle, 1=refreshing
	cfg        *config.Config
	dnsCache   *dns.DNSCache
	geoDB      *geo.GeoIPDB
)

func main() {
	cfg = loadConfig()
	dnsCache = dns.NewDNSCache(cfg.DNSCacheTTL)

	// Set Xray asset directory
	os.Setenv("XRAY_LOCATION_ASSET", cfg.GeoDatDir)

	// Init GeoIPDB from local .mmdb files
	if key := os.Getenv("MAXMIND_LICENSE_KEY"); key != "" {
		if err := geo.AutoDownload(cfg.GeoDBDir, key); err != nil {
			log.Printf("[geoip] auto-download failed: %v", err)
		}
	}
	geoDB = geo.NewGeoIPDB(cfg.GeoDBDir)

	// Apply HWID from env into custom headers
	config.CustomHeaders["X-Hwid"] = cfg.Hwid

	port := cfg.Port
	refreshInterval := cfg.RefreshInterval

	log.Printf("[server] starting on :%d, refresh every %s", port, refreshInterval)

	// Initial refresh
	triggerRefresh()

	// Periodic refresh
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

	// Graceful shutdown
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

func loadConfig() *config.Config {
	c := &config.Config{}
	c.Port, _ = strconv.Atoi(envOr("PORT", "8080"))
	if d, err := time.ParseDuration(envOr("REFRESH_INTERVAL", "30m")); err == nil {
		c.RefreshInterval = d
	} else {
		c.RefreshInterval = 30 * time.Minute
	}
	if v := os.Getenv("SUBSCRIPTION_URLS"); v != "" {
		c.SubscriptionURLs = strings.Split(v, ",")
	} else {
		log.Fatal("[config] SUBSCRIPTION_URLS is required")
	}
	c.NameInclude = envOr("NAME_INCLUDE", "")
	c.NameExclude = envOr("NAME_EXCLUDE", "")
	if d, err := time.ParseDuration(envOr("DNS_TIMEOUT", "2s")); err == nil {
		c.DNSTimeout = d
	}
	if d, err := time.ParseDuration(envOr("DNS_CACHE_TTL", "10m")); err == nil {
		c.DNSCacheTTL = d
	}
	if d, err := time.ParseDuration(envOr("EXIT_PROBE_TIMEOUT", "12s")); err == nil {
		c.ExitProbeTimeout = d
	}
	c.MaxConcurrent, _ = strconv.Atoi(envOr("MAX_CONCURRENT", "50"))
	c.GeoDatDir = envOr("GEO_DAT_DIR", "/usr/local/share/xray")
	c.GeoDBDir = envOr("GEO_DB_DIR", "/usr/local/share/xray")
	c.Hwid = os.Getenv("HWID")
	if c.Hwid == "" {
		log.Fatal("[config] HWID is required")
	}
	return c
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func refreshSubscriptions() {
	start := time.Now()
	log.Printf("[refresh] starting...")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Phase 1: Fetch subscriptions
	fetchResults := fetch.FetchSubscriptions(ctx, cfg.SubscriptionURLs, 15*time.Second)
	sourcesOK := 0
	sourcesFailed := 0
	for _, r := range fetchResults {
		if r.Status == "ok" {
			sourcesOK++
		} else {
			sourcesFailed++
		}
	}

	// Phase 2: Parse
	var allLines []string
	for _, r := range fetchResults {
		allLines = append(allLines, r.Lines...)
	}
	parseResult := parse.ParseAllLines(allLines)
	filtered := parse.ApplyNameFilter(parseResult.Records, cfg.NameInclude, cfg.NameExclude)

	// Phase 3: DNS resolve
	dnsMap := dns.ResolveHosts(ctx, dedupHosts(filtered), 20, cfg.DNSTimeout, dnsCache)

	var resolved []parse.ProxyRecord
	for _, r := range filtered {
		if d, ok := dnsMap[r.Host]; ok && d.IP != "" {
			resolved = append(resolved, r)
		}
	}
	log.Printf("[refresh] parsed=%d filtered=%d dns-resolved=%d (unique-hosts=%d)", len(parseResult.Records), len(filtered), len(resolved), len(dnsMap))

	// Phase 4: Exit-IP probe via Xray (exit-IP geo only, no host-IP fallback)
	var geoRecords []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}
	geoAvailable := 0

	if len(resolved) > 0 {
		ep := exitprobe.NewExitProber(cfg, geoDB)
		if err := ep.StartWithProxies(resolved); err != nil {
			log.Printf("[refresh] xray start failed: %v, skipping probe", err)
		} else {
			exitResults := ep.ProbeAll(ctx, resolved)
			ep.Stop()

			for i, r := range resolved {
				er, probeOK := exitResults[i]
				if !probeOK || !er.XrayOK {
					continue
				}
				isLAN := dnsMap[r.Host] != nil && dnsMap[r.Host].IsPrivate
				var geoInfo *geo.GeoInfo
				geoInfo = er.GeoInfo
				if geoInfo != nil {
					geoAvailable++
				} else if er.ExitLoc != "" {
					geoInfo = &geo.GeoInfo{
						CountryCode: er.ExitLoc,
						City:        er.ExitLoc,
						ISP:         "Unknown",
						IP:          er.ExitIP,
					}
					geoAvailable++
				}
				geoRecords = append(geoRecords, struct {
					Record parse.ProxyRecord
					Geo    *geo.GeoInfo
					IsLAN  bool
				}{r, geoInfo, isLAN})
			}
		}
	}

	// Phase 5: Rename
	renamed := rename.RenameAll(geoRecords)

	totalAlive := len(renamed)
	totalDead := len(resolved) - totalAlive

	output := format.FormatOutput(renamed, format.FormatMetadata{
		TotalFetched:    len(allLines),
		TotalParsed:     len(filtered),
		TotalSkipped:    parseResult.Skipped,
		TotalDuplicates: parseResult.Duplicates,
		TotalAlive:      totalAlive,
		TotalDead:       totalDead,
		SourcesOK:       sourcesOK,
		SourcesFailed:   sourcesFailed,
		GeoAvailable:    geoAvailable,
		GeoTotal:        len(resolved),
	})

	cache.Store(&cachedData{output: output, lastRefresh: time.Now()})
	dnsCache.Purge()
	log.Printf("[refresh] done in %s: %d alive, %d with geo", time.Since(start), totalAlive, geoAvailable)
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

func handleSub(w http.ResponseWriter, r *http.Request) {
	v := cache.Load()
	if v == nil {
		triggerRefresh()
		select {
		case <-time.After(initWaitTimeout):
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
	if time.Since(data.lastRefresh) > cfg.RefreshInterval {
		triggerRefresh()
	}
	body := []byte(data.output)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Last-Refresh", data.lastRefresh.Format(time.RFC3339))
	w.Write(body)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}