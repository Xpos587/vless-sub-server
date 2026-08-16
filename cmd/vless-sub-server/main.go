package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/subview"
)

const initWaitTimeout = 5 * time.Second

var (
	refreshing       atomic.Int32 // 0=idle, 1=refreshing
	countryReprobing atomic.Int32 // 0=idle, 1=reprobing final WARP countries
	cfg              *config.Config
	service          *pipeline.Pipeline
)

func main() {
	cfg = loadConfig()
	service = pipeline.New(cfg, dns.NewDNSCache(cfg.DNSCacheTTL))
	if err := service.LoadCountryState(cfg.CountryStatePath); err != nil {
		log.Printf("[country-state] unavailable; continuing without persisted evidence")
	}
	if err := service.LoadCached(cfg.CacheStatePath); err != nil {
		log.Printf("[subscription-cache] unavailable; refreshing before publish")
	} else if _, ok := service.Cached(); ok {
		log.Printf("[subscription-cache] restored last-known-good subscription")
	}

	// Set Xray asset directory
	os.Setenv("XRAY_LOCATION_ASSET", cfg.GeoDatDir)

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
	countryTicker := time.NewTicker(cfg.CountryReprobeInterval)
	go func() {
		for range countryTicker.C {
			triggerCountryReprobe()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleSub)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/_exit", handleExitObservation)

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
	c, err := config.Load()
	if err != nil {
		log.Fatalf("[config] %v", err)
	}
	return c
}

func refreshSubscriptions() {
	start := time.Now()
	log.Printf("[refresh] starting...")

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	result := service.Refresh(ctx)
	if result.Published {
		if err := service.SaveCached(cfg.CacheStatePath); err != nil {
			log.Printf("[subscription-cache] save failed")
		}
	}
	log.Printf("[refresh] done in %s: parsed=%d resolved=%d good=%d partial=%d dead=%d bandwidth=%d/%d country_direct=%v country_warp=%v country_state_save_failed=%t published=%t", time.Since(start), result.Parsed, result.Resolved, result.Good, result.Partial, result.Dead, result.BandwidthSuccesses, result.BandwidthCandidates, result.DirectCountrySources, result.WarpCountrySources, result.CountryStateSaveFailed, result.Published)
}

func triggerRefresh() {
	if !refreshing.CompareAndSwap(0, 1) {
		return // already refreshing
	}
	go func() {
		defer refreshing.Store(0)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[refresh] panic recovered: %v", r)
			}
		}()
		refreshSubscriptions()
	}()
}

func triggerCountryReprobe() {
	if !countryReprobing.CompareAndSwap(0, 1) {
		return
	}
	go func() {
		defer countryReprobing.Store(0)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[country-reprobe] panic recovered: %v", r)
			}
		}()
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		result := service.ReprobeWarpCountries(ctx)
		log.Printf("[country-reprobe] done in %s: candidates=%d updated=%d country_warp=%v country_state_save_failed=%t", time.Since(start), result.Candidates, result.Updated, result.WarpCountrySources, result.CountryStateSaveFailed)
	}()
}

func handleSub(w http.ResponseWriter, r *http.Request) {
	data, ok := service.Cached()
	if !ok {
		triggerRefresh()
		select {
		case <-time.After(initWaitTimeout):
			data, ok = service.Cached()
		}
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("# initializing...\n"))
			return
		}
	}
	if time.Since(data.LastRefresh) > cfg.RefreshInterval {
		triggerRefresh()
	}

	writeSubscriptionResponse(w, r, data)
}

func writeSubscriptionResponse(w http.ResponseWriter, r *http.Request, data *pipeline.CachedData) {
	client := subview.DetectClient(r.Header.Get("User-Agent"), r.Header.Get("X-Client"))
	options, err := subview.ParseForClient(r.URL.Query(), client)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	response := subview.Render(data, options)
	contentType := "text/plain; charset=utf-8"
	if options.Format != subview.FormatURL {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(response.Body)))
	w.Header().Set("X-Last-Refresh", data.LastRefresh.Format(time.RFC3339))
	w.Header().Set("X-Warp", map[bool]string{true: "on", false: "off"}[options.Warp])
	profile := "none"
	if options.Format != subview.FormatURL {
		profile = string(options.Profile)
	}
	w.Header().Set("X-Profile", profile)
	w.Header().Set("X-Country-Filtered", strconv.Itoa(response.Filtered))
	w.Header().Set("X-Country-Unknown", strconv.Itoa(response.Unknown))
	w.Header().Set("X-Country-Conflict", strconv.Itoa(response.Conflict))
	w.Write(response.Body)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

// handleExitObservation reports the proxy's source address observed at our
// public edge. The endpoint is used only by the in-process probe.
func handleExitObservation(w http.ResponseWriter, r *http.Request) {
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))); err == nil && ip.IsValid() {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{"ip": ip.Unmap().String()})
		return
	}
	forwarded := r.Header.Values("X-Forwarded-For")
	for i := 0; i < len(forwarded); i++ {
		parts := strings.Split(forwarded[i], ",")
		for j := 0; j < len(parts); j++ {
			ip, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err == nil && ip.IsValid() {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				json.NewEncoder(w).Encode(map[string]string{"ip": ip.Unmap().String()})
				return
			}
		}
	}
	w.WriteHeader(http.StatusBadRequest)
}
