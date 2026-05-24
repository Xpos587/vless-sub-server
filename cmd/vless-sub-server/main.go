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
	"github.com/michael/vless-sub-server/internal/probe"
	"github.com/michael/vless-sub-server/internal/rename"
)

var (
	cachedOutput string
	lastRefresh  time.Time
	refreshSF    singleflight.Group
	cfg          *config.Config
)

func main() {
	cfg = loadConfig()

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
	c.SubscriptionURLs = strings.Split(envOr("SUBSCRIPTION_URLS",
		"https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE"), ",")
	c.NameInclude = envOr("NAME_INCLUDE", "")
	c.NameExclude = envOr("NAME_EXCLUDE", "")
	if d, err := time.ParseDuration(envOr("TCP_TIMEOUT", "3s")); err == nil {
		c.TCPTimeout = d
	}
	if d, err := time.ParseDuration(envOr("DNS_TIMEOUT", "2s")); err == nil {
		c.DNSTimeout = d
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

	// Phase 3: DNS
	uniqueHosts := make(map[string]bool)
	for _, r := range filtered {
		uniqueHosts[r.Host] = true
	}
	hostList := make([]string, 0, len(uniqueHosts))
	for h := range uniqueHosts {
		hostList = append(hostList, h)
	}
	dnsMap := dns.ResolveHosts(ctx, hostList, 20, cfg.DNSTimeout)

	var withDNS []parse.ProxyRecord
	for _, r := range filtered {
		if d, ok := dnsMap[r.Host]; ok && d.IP != "" {
			withDNS = append(withDNS, r)
		}
	}

	// Phase 4: TCP probes
	probeHosts := make([]probe.HostSpec, len(withDNS))
	for i, r := range withDNS {
		probeHosts[i] = probe.HostSpec{
			Host: r.Host,
			IP:   dnsMap[r.Host].IP,
			Port: r.Port,
		}
	}
	probeResults := probe.TCPProbeAll(ctx, probeHosts, 20, cfg.TCPTimeout)

	// Collect alive proxies
	var aliveRecords []parse.ProxyRecord
	for _, r := range withDNS {
		key := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if p, ok := probeResults[key]; ok && p.Reachable {
			aliveRecords = append(aliveRecords, r)
		}
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
			for _, r := range aliveRecords {
				isLAN := dnsMap[r.Host] != nil && dnsMap[r.Host].IsPrivate
				geoRecords = append(geoRecords, struct {
					Record parse.ProxyRecord
					Geo    *geo.GeoInfo
					IsLAN  bool
				}{r, nil, isLAN})
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
	} else {
		for _, r := range withDNS {
			isLAN := dnsMap[r.Host] != nil && dnsMap[r.Host].IsPrivate
			geoRecords = append(geoRecords, struct {
				Record parse.ProxyRecord
				Geo    *geo.GeoInfo
				IsLAN  bool
			}{r, nil, isLAN})
		}
	}

	// Phase 6: Rename
	renamed := rename.RenameAll(geoRecords, probeResults)

	totalAlive := len(renamed)
	totalDead := len(withDNS) - totalAlive

	output := format.FormatOutput(renamed, format.FormatMetadata{
		TotalFetched:   len(allLines),
		TotalParsed:    len(filtered),
		TotalSkipped:   parseResult.Skipped,
		TotalDuplicates: parseResult.Duplicates,
		TotalAlive:     totalAlive,
		TotalDead:      totalDead,
		SourcesOK:      sourcesOK,
		SourcesFailed:  sourcesFailed,
		GeoAvailable:   geoAvailable,
		GeoTotal:       len(withDNS),
	})

	cachedOutput = output
	lastRefresh = time.Now()
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