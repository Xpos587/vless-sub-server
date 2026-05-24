package config

import "time"

type Config struct {
	Port             int           `env:"PORT" envDefault:"8080"`
	RefreshInterval  time.Duration `env:"REFRESH_INTERVAL" envDefault:"30m"`
	SubscriptionURLs []string      `env:"SUBSCRIPTION_URLS" envSeparator:"," envDefault:"https://nya.astracat.ru/krQYNf60nkoe-43K,https://sub.volnalink.uk/W5VYy08Uu9T30aTE"`
	NameInclude      string        `env:"NAME_INCLUDE"`
	NameExclude      string        `env:"NAME_EXCLUDE"`
	TCPTimeout       time.Duration `env:"TCP_TIMEOUT" envDefault:"3s"`
	DNSTimeout       time.Duration `env:"DNS_TIMEOUT" envDefault:"2s"`
	DNSCacheTTL      time.Duration `env:"DNS_CACHE_TTL" envDefault:"10m"`
	ExitProbeTimeout time.Duration `env:"EXIT_PROBE_TIMEOUT" envDefault:"12s"`
	MaxConcurrent    int           `env:"MAX_CONCURRENT" envDefault:"50"`
	SocksStartPort   int           `env:"SOCKS_START_PORT" envDefault:"10801"`
	GeoDatDir        string        `env:"GEO_DAT_DIR" envDefault:"/usr/local/share/xray"`
}

var CustomHeaders = map[string]string{
	"User-Agent":      "Happ/1.4.9/Linux",
	"X-App-Version":   "1.4.9",
	"X-Device-Locale": "EN",
	"X-Device-Os":     "Linux",
	"X-Device-Model":  "m7600qe_x86_64",
	"X-Hwid":          "cb46d5c2545131323baa5a7d67cb05c6",
	"X-Ver-Os":        "artix_unknown",
	"Accept-Language":  "en,*",
	"Accept-Encoding":  "identity",
}

var PlaceholderHosts = map[string]bool{
	"example.com": true, "example.org": true,
	"0.0.0.0": true, "127.0.0.1": true,
	"localhost": true, "::1": true,
}
