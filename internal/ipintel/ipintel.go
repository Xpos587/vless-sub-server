package ipintel

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// IP type constants normalized across providers.
const (
	TypeResidential = "residential"
	TypeMobile      = "mobile"
	TypeHosting     = "hosting"
	TypeBusiness    = "business"
	TypeCDN         = "cdn"
	TypeEducation   = "education"
	TypeGovernment  = "government"
	TypeOther       = "other"
	TypeUnknown     = "unknown"
)

// Reputation level normalized across providers.
const (
	RiskClean      = "clean"
	RiskSuspicious = "suspicious"
	RiskRisky      = "risky"
	RiskUnknown    = "unknown"
)

// Flags are the reputation signals merged from all providers.
type Flags struct {
	Proxy      bool
	VPN        bool
	Tor        bool
	Abuser     bool
	Datacenter bool
	Crawler    bool
}

// Intel is the normalized reputation and classification of an exit IP.
// It is cacheable and contains no subscription identity or credentials.
type Intel struct {
	IP           string
	ASN          string
	Organization string
	ISP          string
	CountryCode  string
	City         string
	Type         string
	RiskLevel    string
	RiskScore    float64
	Flags        Flags
	Sources      []string
	CheckedAt    time.Time
}

// Result is one provider's normalized contribution.
type Result struct {
	Source       string
	ASN          string
	Organization string
	ISP          string
	CountryCode  string
	City         string
	Type         string
	Proxy        bool
	VPN          bool
	Tor          bool
	Abuser       bool
	Datacenter   bool
	Crawler      bool
	RiskScore    float64
	HasScore     bool
}

// Provider looks up reputation data for a single public IP.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, ip netip.Addr) (Result, bool)
}

type detailedProvider interface {
	LookupDetailed(context.Context, netip.Addr) (Result, ProviderOutcome)
}

type ProviderOutcome string

const (
	ProviderSuccess    ProviderOutcome = "success"
	ProviderQuota      ProviderOutcome = "quota"
	ProviderHTTPError  ProviderOutcome = "http_error"
	ProviderParseError ProviderOutcome = "parse_error"
	ProviderTransport  ProviderOutcome = "transport"
)

// Aggregator merges several providers into one Intel and caches by IP.
type Aggregator struct {
	providers []Provider
	cache     *cache
	statsMu   sync.RWMutex
	stats     map[providerStatKey]uint64
}

type providerStatKey struct {
	provider string
	outcome  ProviderOutcome
}

type ProviderStat struct {
	Provider string
	Outcome  ProviderOutcome
	Count    uint64
}

// NewAggregator returns an aggregator that calls the given providers
// concurrently and caches results for cacheTTL.
func NewAggregator(providers []Provider, cacheTTL time.Duration) *Aggregator {
	return &Aggregator{providers: providers, cache: newCache(cacheTTL), stats: make(map[providerStatKey]uint64)}
}

// Lookup returns a normalized Intel for ip. It never writes subscription
// identity; the cache key is the public IP only.
func (a *Aggregator) Lookup(ctx context.Context, ip netip.Addr) (Intel, bool) {
	key := ip.Unmap().String()
	if intel, ok := a.cache.get(key); ok {
		return intel, true
	}

	var mu sync.Mutex
	results := make([]Result, 0, len(a.providers))
	var wg sync.WaitGroup
	for _, provider := range a.providers {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			var result Result
			outcome := ProviderTransport
			if detailed, ok := p.(detailedProvider); ok {
				result, outcome = detailed.LookupDetailed(ctx, ip)
			} else if value, ok := p.Lookup(ctx, ip); ok {
				result, outcome = value, ProviderSuccess
			}
			a.RecordProvider(p.Name(), outcome)
			if outcome != ProviderSuccess {
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(provider)
	}
	wg.Wait()

	if len(results) == 0 {
		return Intel{}, false
	}
	intel := merge(results, ip)
	a.cache.set(key, intel)
	return intel, true
}

func (a *Aggregator) RecordProvider(provider string, outcome ProviderOutcome) {
	if a == nil || provider == "" || outcome == "" {
		return
	}
	a.statsMu.Lock()
	if a.stats == nil {
		a.stats = make(map[providerStatKey]uint64)
	}
	a.stats[providerStatKey{provider: provider, outcome: outcome}]++
	a.statsMu.Unlock()
}

func (a *Aggregator) ProviderStats() []ProviderStat {
	if a == nil {
		return nil
	}
	a.statsMu.RLock()
	stats := make([]ProviderStat, 0, len(a.stats))
	for key, count := range a.stats {
		stats = append(stats, ProviderStat{Provider: key.provider, Outcome: key.outcome, Count: count})
	}
	a.statsMu.RUnlock()
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Provider != stats[j].Provider {
			return stats[i].Provider < stats[j].Provider
		}
		return stats[i].Outcome < stats[j].Outcome
	})
	return stats
}

func merge(results []Result, ip netip.Addr) Intel {
	flags := Flags{}
	sources := make([]string, 0, len(results))
	maxScore := 0.0
	hasScore := false
	seen := make(map[string]struct{}, len(results))

	for _, result := range results {
		flags.Proxy = flags.Proxy || result.Proxy
		flags.VPN = flags.VPN || result.VPN
		flags.Tor = flags.Tor || result.Tor
		flags.Abuser = flags.Abuser || result.Abuser
		flags.Datacenter = flags.Datacenter || result.Datacenter
		flags.Crawler = flags.Crawler || result.Crawler
		if result.HasScore {
			hasScore = true
			if result.RiskScore > maxScore {
				maxScore = result.RiskScore
			}
		}
		if _, ok := seen[result.Source]; !ok {
			seen[result.Source] = struct{}{}
			sources = append(sources, result.Source)
		}
	}

	intel := Intel{
		IP:        ip.Unmap().String(),
		Type:      normalizeType(results, flags),
		RiskLevel: classifyRisk(flags, len(results) > 0),
		RiskScore: compositeScore(flags),
		Flags:     flags,
		Sources:   sources,
		CheckedAt: time.Now(),
	}
	if hasScore && maxScore > intel.RiskScore {
		intel.RiskScore = maxScore
	}

	for _, result := range results {
		if intel.ASN == "" && result.ASN != "" {
			intel.ASN = result.ASN
		}
		if intel.Organization == "" && result.Organization != "" {
			intel.Organization = result.Organization
		}
		if intel.ISP == "" && result.ISP != "" {
			intel.ISP = result.ISP
		}
		if intel.CountryCode == "" && result.CountryCode != "" {
			intel.CountryCode = result.CountryCode
		}
		if intel.City == "" && result.City != "" {
			intel.City = result.City
		}
	}
	return intel
}

func normalizeType(results []Result, flags Flags) string {
	hasMobile := false
	hasBusiness := false
	hasEducation := false
	hasGovernment := false
	hasCDN := false
	for _, result := range results {
		switch result.Type {
		case TypeMobile:
			hasMobile = true
		case TypeBusiness:
			hasBusiness = true
		case TypeEducation:
			hasEducation = true
		case TypeGovernment:
			hasGovernment = true
		case TypeCDN:
			hasCDN = true
		}
	}
	if flags.Datacenter || hasProviderType(results, TypeHosting) {
		return TypeHosting
	}
	if hasMobile {
		return TypeMobile
	}
	if hasCDN {
		return TypeCDN
	}
	if hasBusiness {
		return TypeBusiness
	}
	if hasEducation {
		return TypeEducation
	}
	if hasGovernment {
		return TypeGovernment
	}
	if len(results) > 0 {
		return TypeResidential
	}
	return TypeUnknown
}

func hasProviderType(results []Result, t string) bool {
	for _, result := range results {
		if result.Type == t {
			return true
		}
	}
	return false
}

func classifyRisk(flags Flags, hasData bool) string {
	if !hasData {
		return RiskUnknown
	}
	if flags.Abuser || flags.Tor {
		return RiskRisky
	}
	if flags.Proxy || flags.VPN || flags.Datacenter {
		return RiskSuspicious
	}
	return RiskClean
}

// compositeScore is an internal 0..100 signal derived from flags. It is not a
// provider score; it is a stable fallback when no provider returns one.
func compositeScore(flags Flags) float64 {
	score := 0.0
	if flags.Proxy {
		score += 25
	}
	if flags.VPN {
		score += 25
	}
	if flags.Datacenter {
		score += 10
	}
	if flags.Abuser {
		score += 40
	}
	if flags.Tor {
		score += 35
	}
	if flags.Crawler {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	return score
}

// MergeResult merges a provider result into an existing Intel. It is used when
// a secondary provider (e.g. check.place through a proxy) is added after the
// primary aggregator has already returned an Intel.
func MergeResult(intel Intel, result Result) Intel {
	intel.Flags.Proxy = intel.Flags.Proxy || result.Proxy
	intel.Flags.VPN = intel.Flags.VPN || result.VPN
	intel.Flags.Tor = intel.Flags.Tor || result.Tor
	intel.Flags.Abuser = intel.Flags.Abuser || result.Abuser
	intel.Flags.Datacenter = intel.Flags.Datacenter || result.Datacenter
	intel.Flags.Crawler = intel.Flags.Crawler || result.Crawler
	if result.HasScore && result.RiskScore > intel.RiskScore {
		intel.RiskScore = result.RiskScore
	}
	if result.Datacenter || result.Type == TypeHosting {
		intel.Type = TypeHosting
	} else if intel.Type == "" && result.Type != "" {
		intel.Type = result.Type
	} else if intel.Type == TypeResidential && result.Type != "" && result.Type != TypeResidential {
		intel.Type = result.Type
	}
	if intel.ASN == "" && result.ASN != "" {
		intel.ASN = result.ASN
	}
	if intel.Organization == "" && result.Organization != "" {
		intel.Organization = result.Organization
	}
	if intel.ISP == "" && result.ISP != "" {
		intel.ISP = result.ISP
	}
	if intel.CountryCode == "" && result.CountryCode != "" {
		intel.CountryCode = result.CountryCode
	}
	if intel.City == "" && result.City != "" {
		intel.City = result.City
	}
	if result.Source != "" {
		seen := false
		for _, source := range intel.Sources {
			if source == result.Source {
				seen = true
				break
			}
		}
		if !seen {
			intel.Sources = append(intel.Sources, result.Source)
		}
	}
	intel.RiskLevel = classifyRisk(intel.Flags, true)
	intel.RiskScore = maxF(intel.RiskScore, compositeScore(intel.Flags))
	return intel
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
