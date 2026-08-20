package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                   int           `env:"PORT" envDefault:"8080"`
	RefreshInterval        time.Duration `env:"REFRESH_INTERVAL" envDefault:"30m"`
	SubscriptionURLs       []string      `env:"SUBSCRIPTION_URLS,required" envSeparator:","`
	NameInclude            string        `env:"NAME_INCLUDE"`
	NameExclude            string        `env:"NAME_EXCLUDE"`
	DNSTimeout             time.Duration `env:"DNS_TIMEOUT" envDefault:"2s"`
	DNSCacheTTL            time.Duration `env:"DNS_CACHE_TTL" envDefault:"10m"`
	ExitProbeTimeout       time.Duration `env:"EXIT_PROBE_TIMEOUT" envDefault:"12s"`
	ProbeSampleCount       int           `env:"PROBE_SAMPLE_COUNT" envDefault:"5"`
	ProbeSampleGap         time.Duration `env:"PROBE_SAMPLE_GAP" envDefault:"100ms"`
	ProbeSampleTimeout     time.Duration `env:"PROBE_SAMPLE_TIMEOUT" envDefault:"5s"`
	BandwidthEnabled       bool          `env:"BANDWIDTH_ENABLED" envDefault:"true"`
	BandwidthBytes         int64         `env:"BANDWIDTH_BYTES" envDefault:"1048576"`
	BandwidthBudget        int64         `env:"BANDWIDTH_BUDGET_BYTES" envDefault:"33554432"`
	BandwidthTimeout       time.Duration `env:"BANDWIDTH_TIMEOUT" envDefault:"8s"`
	BandwidthRefreshAfter  time.Duration `env:"BANDWIDTH_REFRESH_AFTER" envDefault:"2h"`
	BandwidthRetryAfter    time.Duration `env:"BANDWIDTH_RETRY_AFTER" envDefault:"30m"`
	SourceStaleMaxAge      time.Duration `env:"SOURCE_STALE_MAX_AGE" envDefault:"6h"`
	CountryStatePath       string        `env:"COUNTRY_STATE_PATH"`
	CacheStatePath         string        `env:"CACHE_STATE_PATH"`
	CountryReprobeInterval time.Duration `env:"COUNTRY_REPROBE_INTERVAL" envDefault:"5m"`
	ExitObserverURL        string        `env:"EXIT_OBSERVER_URL" envDefault:"https://exit-observer.hypcat.net/_exit"`
	MaxConcurrent          int           `env:"MAX_CONCURRENT" envDefault:"50"`
	GeoDatDir              string        `env:"GEO_DAT_DIR" envDefault:"/usr/local/share/xray"`
	Hwid                   string        `env:"HWID,required"`
	SourceAliases          []string      `env:"SOURCE_ALIASES" envSeparator:","`
	MetricsPort            int           `env:"METRICS_PORT" envDefault:"9090"`
	FetchProxyFallback     bool          `env:"FETCH_PROXY_FALLBACK" envDefault:"true"`
	SourceFetchProxies     []string      `env:"SOURCE_FETCH_PROXIES" envSeparator:","`
	IPIntelEnabled         bool          `env:"IP_INTEL_ENABLED" envDefault:"true"`
	IPIntelTimeout         time.Duration `env:"IP_INTEL_TIMEOUT" envDefault:"8s"`
	IPIntelCacheTTL        time.Duration `env:"IP_INTEL_CACHE_TTL" envDefault:"6h"`
	IPIntelMaxConcurrent   int           `env:"IP_INTEL_MAX_CONCURRENT" envDefault:"8"`
	IPIntelCheckPlace      bool          `env:"IP_INTEL_CHECK_PLACE" envDefault:"false"`
	IPIntelProxyURL        string        `env:"IP_INTEL_PROXY_URL"`
	ServiceCheckEnabled    bool          `env:"SERVICE_CHECK_ENABLED" envDefault:"false"`
	ServiceCheckTimeout    time.Duration `env:"SERVICE_CHECK_TIMEOUT" envDefault:"10s"`
	ServiceCheckMaxConcurrent int       `env:"SERVICE_CHECK_MAX_CONCURRENT" envDefault:"4"`
	ServiceCheckInterval      time.Duration `env:"SERVICE_CHECK_INTERVAL" envDefault:"10m"`
	ServiceCheckBatchSize     int           `env:"SERVICE_CHECK_BATCH_SIZE" envDefault:"20"`
	ServiceCheckCacheTTL      time.Duration `env:"SERVICE_CHECK_CACHE_TTL" envDefault:"2h"`
	PortCheckEnabled         bool          `env:"PORT_CHECK_ENABLED" envDefault:"false"`
	PortCheckTimeout         time.Duration `env:"PORT_CHECK_TIMEOUT" envDefault:"3s"`
	PortCheckMaxConcurrent   int           `env:"PORT_CHECK_MAX_CONCURRENT" envDefault:"4"`
	DNSBLEnabled             bool          `env:"DNSBL_ENABLED" envDefault:"false"`
	DNSBLTimeout             time.Duration `env:"DNSBL_TIMEOUT" envDefault:"3s"`
	DNSBLMaxConcurrent       int           `env:"DNSBL_MAX_CONCURRENT" envDefault:"4"`
}

func Load() (*Config, error) {
	c := &Config{
		Port:                   8080,
		RefreshInterval:        30 * time.Minute,
		DNSTimeout:             2 * time.Second,
		DNSCacheTTL:            10 * time.Minute,
		ExitProbeTimeout:       12 * time.Second,
		ProbeSampleCount:       5,
		ProbeSampleGap:         100 * time.Millisecond,
		ProbeSampleTimeout:     5 * time.Second,
		BandwidthEnabled:       true,
		BandwidthBytes:         1 << 20,
		BandwidthBudget:        32 << 20,
		BandwidthTimeout:       8 * time.Second,
		BandwidthRefreshAfter:  2 * time.Hour,
		BandwidthRetryAfter:    30 * time.Minute,
		SourceStaleMaxAge:      6 * time.Hour,
		CountryReprobeInterval: 5 * time.Minute,
		ExitObserverURL:        "https://exit-observer.hypcat.net/_exit",
		MaxConcurrent:          50,
		GeoDatDir:              "/usr/local/share/xray",
		IPIntelEnabled:         true,
		IPIntelTimeout:         8 * time.Second,
		IPIntelCacheTTL:        6 * time.Hour,
		IPIntelMaxConcurrent:   8,
		ServiceCheckEnabled:    false,
		ServiceCheckTimeout:    10 * time.Second,
		ServiceCheckMaxConcurrent: 4,
		ServiceCheckInterval:      10 * time.Minute,
		ServiceCheckBatchSize:     20,
		ServiceCheckCacheTTL:      2 * time.Hour,
		PortCheckEnabled:         false,
		PortCheckTimeout:         3 * time.Second,
		PortCheckMaxConcurrent:   4,
		DNSBLEnabled:             false,
		DNSBLTimeout:             3 * time.Second,
		DNSBLMaxConcurrent:       4,
	}
	if raw := os.Getenv("SUBSCRIPTION_URLS"); raw == "" {
		return nil, fmt.Errorf("SUBSCRIPTION_URLS is required")
	} else {
		c.SubscriptionURLs = strings.Split(raw, ",")
	}
	if c.Hwid = os.Getenv("HWID"); c.Hwid == "" {
		return nil, fmt.Errorf("HWID is required")
	}
	c.NameInclude, c.NameExclude = os.Getenv("NAME_INCLUDE"), os.Getenv("NAME_EXCLUDE")
	var err error
	if c.Port, err = intEnv("PORT", c.Port); err != nil {
		return nil, err
	}
	if c.MetricsPort, err = intEnv("METRICS_PORT", 9090); err != nil || c.MetricsPort < 0 || c.MetricsPort > 65535 {
		return nil, fmt.Errorf("METRICS_PORT must be a valid port or 0 to disable")
	}
	if raw := os.Getenv("SOURCE_ALIASES"); raw != "" {
		c.SourceAliases = strings.Split(raw, ",")
	}
	if raw := os.Getenv("SOURCE_FETCH_PROXIES"); raw != "" {
		c.SourceFetchProxies = strings.Split(raw, ",")
	}
	if raw := os.Getenv("IP_INTEL_ENABLED"); raw != "" {
		if c.IPIntelEnabled, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("IP_INTEL_ENABLED: %w", err)
		}
	}
	if c.IPIntelTimeout, err = durationEnv("IP_INTEL_TIMEOUT", c.IPIntelTimeout); err != nil || c.IPIntelTimeout <= 0 {
		return nil, fmt.Errorf("IP_INTEL_TIMEOUT must be positive")
	}
	if c.IPIntelCacheTTL, err = durationEnv("IP_INTEL_CACHE_TTL", c.IPIntelCacheTTL); err != nil || c.IPIntelCacheTTL <= 0 {
		return nil, fmt.Errorf("IP_INTEL_CACHE_TTL must be positive")
	}
	if c.IPIntelMaxConcurrent, err = intEnv("IP_INTEL_MAX_CONCURRENT", c.IPIntelMaxConcurrent); err != nil || c.IPIntelMaxConcurrent < 1 {
		return nil, fmt.Errorf("IP_INTEL_MAX_CONCURRENT must be positive")
	}
	c.IPIntelProxyURL = os.Getenv("IP_INTEL_PROXY_URL")
	if raw := os.Getenv("SERVICE_CHECK_ENABLED"); raw != "" {
		if c.ServiceCheckEnabled, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("SERVICE_CHECK_ENABLED: %w", err)
		}
	}
	if c.ServiceCheckTimeout, err = durationEnv("SERVICE_CHECK_TIMEOUT", c.ServiceCheckTimeout); err != nil || c.ServiceCheckTimeout <= 0 {
		return nil, fmt.Errorf("SERVICE_CHECK_TIMEOUT must be positive")
	}
	if c.ServiceCheckMaxConcurrent, err = intEnv("SERVICE_CHECK_MAX_CONCURRENT", c.ServiceCheckMaxConcurrent); err != nil || c.ServiceCheckMaxConcurrent < 1 {
		return nil, fmt.Errorf("SERVICE_CHECK_MAX_CONCURRENT must be positive")
	}
	if c.ServiceCheckInterval, err = durationEnv("SERVICE_CHECK_INTERVAL", c.ServiceCheckInterval); err != nil || c.ServiceCheckInterval <= 0 {
		return nil, fmt.Errorf("SERVICE_CHECK_INTERVAL must be positive")
	}
	if c.ServiceCheckBatchSize, err = intEnv("SERVICE_CHECK_BATCH_SIZE", c.ServiceCheckBatchSize); err != nil || c.ServiceCheckBatchSize < 1 {
		return nil, fmt.Errorf("SERVICE_CHECK_BATCH_SIZE must be positive")
	}
	if c.ServiceCheckCacheTTL, err = durationEnv("SERVICE_CHECK_CACHE_TTL", c.ServiceCheckCacheTTL); err != nil || c.ServiceCheckCacheTTL <= 0 {
		return nil, fmt.Errorf("SERVICE_CHECK_CACHE_TTL must be positive")
	}
	if raw := os.Getenv("PORT_CHECK_ENABLED"); raw != "" {
		if c.PortCheckEnabled, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("PORT_CHECK_ENABLED: %w", err)
		}
	}
	if c.PortCheckTimeout, err = durationEnv("PORT_CHECK_TIMEOUT", c.PortCheckTimeout); err != nil || c.PortCheckTimeout <= 0 {
		return nil, fmt.Errorf("PORT_CHECK_TIMEOUT must be positive")
	}
	if c.PortCheckMaxConcurrent, err = intEnv("PORT_CHECK_MAX_CONCURRENT", c.PortCheckMaxConcurrent); err != nil || c.PortCheckMaxConcurrent < 1 {
		return nil, fmt.Errorf("PORT_CHECK_MAX_CONCURRENT must be positive")
	}
	if raw := os.Getenv("DNSBL_ENABLED"); raw != "" {
		if c.DNSBLEnabled, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("DNSBL_ENABLED: %w", err)
		}
	}
	if c.DNSBLTimeout, err = durationEnv("DNSBL_TIMEOUT", c.DNSBLTimeout); err != nil || c.DNSBLTimeout <= 0 {
		return nil, fmt.Errorf("DNSBL_TIMEOUT must be positive")
	}
	if c.DNSBLMaxConcurrent, err = intEnv("DNSBL_MAX_CONCURRENT", c.DNSBLMaxConcurrent); err != nil || c.DNSBLMaxConcurrent < 1 {
		return nil, fmt.Errorf("DNSBL_MAX_CONCURRENT must be positive")
	}
	if raw := os.Getenv("IP_INTEL_CHECK_PLACE"); raw != "" {
		if c.IPIntelCheckPlace, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("IP_INTEL_CHECK_PLACE: %w", err)
		}
	}
	if c.MaxConcurrent, err = intEnv("MAX_CONCURRENT", c.MaxConcurrent); err != nil || c.MaxConcurrent < 1 {
		return nil, fmt.Errorf("MAX_CONCURRENT must be positive")
	}
	if c.ProbeSampleCount, err = intEnv("PROBE_SAMPLE_COUNT", c.ProbeSampleCount); err != nil || c.ProbeSampleCount < 1 || c.ProbeSampleCount > 10 {
		return nil, fmt.Errorf("PROBE_SAMPLE_COUNT must be between 1 and 10")
	}
	if c.RefreshInterval, err = durationEnv("REFRESH_INTERVAL", c.RefreshInterval); err != nil {
		return nil, err
	}
	if c.DNSTimeout, err = durationEnv("DNS_TIMEOUT", c.DNSTimeout); err != nil {
		return nil, err
	}
	if c.DNSCacheTTL, err = durationEnv("DNS_CACHE_TTL", c.DNSCacheTTL); err != nil {
		return nil, err
	}
	if c.ExitProbeTimeout, err = durationEnv("EXIT_PROBE_TIMEOUT", c.ExitProbeTimeout); err != nil || c.ExitProbeTimeout <= 0 {
		return nil, fmt.Errorf("EXIT_PROBE_TIMEOUT must be positive")
	}
	if c.ProbeSampleGap, err = durationEnv("PROBE_SAMPLE_GAP", c.ProbeSampleGap); err != nil || c.ProbeSampleGap < 0 || c.ProbeSampleGap > 2*time.Second {
		return nil, fmt.Errorf("PROBE_SAMPLE_GAP must be between 0 and 2s")
	}
	if c.ProbeSampleTimeout, err = durationEnv("PROBE_SAMPLE_TIMEOUT", c.ProbeSampleTimeout); err != nil || c.ProbeSampleTimeout <= 0 {
		return nil, fmt.Errorf("PROBE_SAMPLE_TIMEOUT must be positive")
	}
	if c.BandwidthTimeout, err = durationEnv("BANDWIDTH_TIMEOUT", c.BandwidthTimeout); err != nil || c.BandwidthTimeout <= 0 {
		return nil, fmt.Errorf("BANDWIDTH_TIMEOUT must be positive")
	}
	if c.BandwidthRefreshAfter, err = durationEnv("BANDWIDTH_REFRESH_AFTER", c.BandwidthRefreshAfter); err != nil || c.BandwidthRefreshAfter <= 0 {
		return nil, fmt.Errorf("BANDWIDTH_REFRESH_AFTER must be positive")
	}
	if c.BandwidthRetryAfter, err = durationEnv("BANDWIDTH_RETRY_AFTER", c.BandwidthRetryAfter); err != nil || c.BandwidthRetryAfter <= 0 {
		return nil, fmt.Errorf("BANDWIDTH_RETRY_AFTER must be positive")
	}
	if c.SourceStaleMaxAge, err = durationEnv("SOURCE_STALE_MAX_AGE", c.SourceStaleMaxAge); err != nil || c.SourceStaleMaxAge <= 0 {
		return nil, fmt.Errorf("SOURCE_STALE_MAX_AGE must be positive")
	}
	if c.CountryReprobeInterval, err = durationEnv("COUNTRY_REPROBE_INTERVAL", c.CountryReprobeInterval); err != nil || c.CountryReprobeInterval <= 0 {
		return nil, fmt.Errorf("COUNTRY_REPROBE_INTERVAL must be positive")
	}
	c.CountryStatePath = os.Getenv("COUNTRY_STATE_PATH")
	c.CacheStatePath = os.Getenv("CACHE_STATE_PATH")
	if value := os.Getenv("EXIT_OBSERVER_URL"); value != "" {
		c.ExitObserverURL = value
	}
	if c.BandwidthBytes, err = int64Env("BANDWIDTH_BYTES", c.BandwidthBytes); err != nil || c.BandwidthBytes < 64<<10 || c.BandwidthBytes > 8<<20 {
		return nil, fmt.Errorf("BANDWIDTH_BYTES must be between 64KiB and 8MiB")
	}
	if c.BandwidthBudget, err = int64Env("BANDWIDTH_BUDGET_BYTES", c.BandwidthBudget); err != nil || c.BandwidthBudget < c.BandwidthBytes || c.BandwidthBudget > 32<<20 {
		return nil, fmt.Errorf("BANDWIDTH_BUDGET_BYTES must be between one probe and 32MiB")
	}
	if raw := os.Getenv("BANDWIDTH_ENABLED"); raw != "" {
		if c.BandwidthEnabled, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("BANDWIDTH_ENABLED: %w", err)
		}
	}
	if raw := os.Getenv("FETCH_PROXY_FALLBACK"); raw != "" {
		if c.FetchProxyFallback, err = strconv.ParseBool(raw); err != nil {
			return nil, fmt.Errorf("FETCH_PROXY_FALLBACK: %w", err)
		}
	} else {
		c.FetchProxyFallback = true
	}
	if value := os.Getenv("GEO_DAT_DIR"); value != "" {
		c.GeoDatDir = value
	}
	return c, nil
}

func int64Env(name string, fallback int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func intEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

var CustomHeaders = map[string]string{
	"User-Agent":      "Happ/1.4.9/Linux",
	"X-App-Version":   "1.4.9",
	"X-Device-Locale": "EN",
	"X-Device-Os":     "Linux",
	"X-Device-Model":  "m7600qe_x86_64",
	"X-Hwid":          "", // populated at runtime from Config.Hwid
	"X-Ver-Os":        "artix_unknown",
	"Accept-Language": "en,*",
}

var PlaceholderHosts = map[string]bool{
	"example.com": true, "example.org": true,
	"0.0.0.0": true, "127.0.0.1": true,
	"localhost": true, "::1": true,
}

// SourceAlias names a subscription source for metrics labels. Explicit
// aliases (SOURCE_ALIASES, same order as SUBSCRIPTION_URLS) win; the fallback
// is a short hash so upstream URLs and their tokens never leak into metrics.
func (c *Config) SourceAlias(index int) string {
	if index < len(c.SourceAliases) {
		if alias := strings.TrimSpace(c.SourceAliases[index]); alias != "" {
			return alias
		}
	}
	if index < len(c.SubscriptionURLs) {
		sum := sha256.Sum256([]byte(c.SubscriptionURLs[index]))
		return hex.EncodeToString(sum[:])[:8]
	}
	return fmt.Sprintf("source-%d", index)
}

// FetchProxyURL returns the dedicated fetch proxy (socks5 URL) assigned to a
// source by position in SOURCE_FETCH_PROXIES, or "" for direct egress.
func (c *Config) FetchProxyURL(index int) string {
	if index < len(c.SourceFetchProxies) {
		return strings.TrimSpace(c.SourceFetchProxies[index])
	}
	return ""
}
