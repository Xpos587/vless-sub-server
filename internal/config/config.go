package config

import (
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
