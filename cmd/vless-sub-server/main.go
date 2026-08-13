package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
	refreshing atomic.Int32 // 0=idle, 1=refreshing
	cfg        *config.Config
	service    *pipeline.Pipeline
)

func main() {
	cfg = loadConfig()
	service = pipeline.New(cfg, dns.NewDNSCache(cfg.DNSCacheTTL))
	if err := service.LoadCountryState(cfg.CountryStatePath); err != nil {
		log.Printf("[country-state] unavailable; continuing without persisted evidence")
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
	options, err := subview.Parse(r.URL.Query())
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	response := subview.Render(data, options)
	contentType := "text/plain; charset=utf-8"
	if options.Format == subview.FormatJSON {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(response.Body)))
	w.Header().Set("X-Last-Refresh", data.LastRefresh.Format(time.RFC3339))
	w.Header().Set("X-Warp", map[bool]string{true: "on", false: "off"}[options.Warp])
	w.Header().Set("X-Country-Filtered", strconv.Itoa(response.Filtered))
	w.Header().Set("X-Country-Unknown", strconv.Itoa(response.Unknown))
	w.Header().Set("X-Country-Conflict", strconv.Itoa(response.Conflict))
	w.Write(response.Body)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}
