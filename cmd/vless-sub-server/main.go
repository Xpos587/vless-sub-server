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
	"syscall"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/fetch"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/probe"
	"github.com/michael/vless-sub-server/internal/rename"
)

var (
	cachedOutput string
	lastRefresh  time.Time
	refreshSF    singleflight.Group
	cfg          *config.Config
	dnsCache     *dns.DNSCache
)

func main() {
	cfg = loadConfig()
	dnsCache = dns.NewDNSCache(cfg.DNSCacheTTL)

	// Set Xray asset directory
	os.Setenv("XRAY_LOCATION_ASSET", cfg.GeoDatDir)

	port := cfg.Port
	refreshInterval := cfg.RefreshInterval

	log.Printf("[server] starting on :%d, refresh every %s", port, refreshInterval)

	// Initial refresh
	go func() {
		refreshSF.Do("refresh", func() (interface{}, error) {
			refreshSubscriptions()
			return nil, nil
		})
	}()

	// Periodic refresh
	ticker := time.NewTicker(refreshInterval)
	go func() {
		for range ticker.C {
			refreshSF.Do("refresh", func() (interface{}, error) {
				refreshSubscriptions()
				return nil, nil
			})
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/sub", handleSub)
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
	if d, err := time.ParseDuration(envOr("TCP_TIMEOUT", "3s")); err == nil {
		c.TCPTimeout = d
	}
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
	c.SocksStartPort, _ = strconv.Atoi(envOr("SOCKS_START_PORT", "10801"))
	c.GeoDatDir = envOr("GEO_DAT_DIR", "/usr/local/share/xray")
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
	fetchResults := fetch.FetchSubscriptions(ctx, cfg.SubscriptionURLs, 8*time.Second)
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

	// Phase 3+4: DNS resolve + TCP probe (via pipeline package)
	result := pipeline.ProbeAndFilterStream(ctx, filtered, 20, cfg.DNSTimeout, cfg.TCPTimeout, dnsCache)
	aliveProxies := result.Alive

	// Reconstruct dnsMap from pipeline results (needed for geo isLAN checks)
	dnsMap := make(map[string]*dns.DNSResult)
	for _, p := range aliveProxies {
		if p.DNS != nil {
			dnsMap[p.Record.Host] = p.DNS
		}
	}

	// Reconstruct probeResults for rename.RenameAll
	probeResults := make(map[string]*probe.ProbeResult)
	for _, p := range aliveProxies {
		key := fmt.Sprintf("%s:%d", p.Record.Host, p.Record.Port)
		probeResults[key] = p.Probe
	}

	var aliveRecords []parse.ProxyRecord
	for _, p := range aliveProxies {
		aliveRecords = append(aliveRecords, p.Record)
	}

	// Phase 5: Exit-IP probe via Xray
	var geoRecords []struct {
		Record parse.ProxyRecord
		Geo    *geo.GeoInfo
		IsLAN  bool
	}
	geoAvailable := 0

	if len(aliveRecords) > 0 {
		ep := exitprobe.NewExitProber(cfg)
		if err := ep.StartWithProxies(aliveRecords); err != nil {
			log.Printf("[refresh] xray start failed: %v, proceeding without exit-IP geo", err)
			for _, p := range aliveProxies {
				geoRecords = append(geoRecords, struct {
					Record parse.ProxyRecord
					Geo    *geo.GeoInfo
					IsLAN  bool
				}{p.Record, nil, p.IsLAN})
			}
		} else {
			exitResults := ep.ProbeAll(ctx, aliveRecords)
			ep.Stop()

			for i, r := range aliveRecords {
				isLAN := dnsMap[r.Host] != nil && dnsMap[r.Host].IsPrivate
				var geoInfo *geo.GeoInfo
				if er, ok := exitResults[i]; ok && er.XrayOK {
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
				}
				geoRecords = append(geoRecords, struct {
					Record parse.ProxyRecord
					Geo    *geo.GeoInfo
					IsLAN  bool
				}{r, geoInfo, isLAN})
			}
		}
	}

	// Phase 6: Rename
	renamed := rename.RenameAll(geoRecords, probeResults)

	totalAlive := len(renamed)
	totalDead := result.DNSResolved - totalAlive

	output := format.FormatOutput(renamed, format.FormatMetadata{
		TotalFetched:    len(allLines),
		TotalParsed:     len(filtered),
		TotalSkipped:    parseResult.Skipped,
		TotalDuplicates:  parseResult.Duplicates,
		TotalAlive:      totalAlive,
		TotalDead:       totalDead,
		SourcesOK:       sourcesOK,
		SourcesFailed:   sourcesFailed,
		GeoAvailable:    geoAvailable,
		GeoTotal:        result.DNSResolved,
	})

	cachedOutput = output
	lastRefresh = time.Now()
	dnsCache.Purge()
	log.Printf("[refresh] done in %s: %d alive, %d with geo", time.Since(start), totalAlive, geoAvailable)
}

func handleSub(w http.ResponseWriter, r *http.Request) {
	if cachedOutput == "" {
		refreshSF.Do("refresh", func() (interface{}, error) {
			refreshSubscriptions()
			return nil, nil
		})
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Last-Refresh", lastRefresh.Format(time.RFC3339))
	w.Write([]byte(cachedOutput))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}