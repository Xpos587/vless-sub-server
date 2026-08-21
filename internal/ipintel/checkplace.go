package ipintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

const checkPlaceUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

// CheckPlace mirrors the IPQuality aggregation gateway at ipinfo.check.place.
// It is not in DefaultProviders because Cloudflare blocks datacenter IPs;
// construct it with an *http.Client routed through a residential proxy.
type CheckPlace struct {
	client    *http.Client
	endpoint  string
	databases []string
}

// NewCheckPlace returns a provider that queries AbuseIPDB, IP2Location, ipdata,
// IPQS, and Scamalytics through the check.place gateway. Pass an *http.Client
// whose transport exits through a residential proxy; direct datacenter access
// is typically blocked by Cloudflare.
func NewCheckPlace(client *http.Client) *CheckPlace {
	if client == nil {
		client = http.DefaultClient
	}
	return &CheckPlace{
		client:    client,
		endpoint:  "https://ipinfo.check.place",
		databases: []string{"abuseipdb", "ip2location", "ipdata", "ipqualityscore", "scamalytics"},
	}
}

func (p *CheckPlace) Name() string { return "check.place" }

// Probe performs one lightweight database query to determine whether the
// wrapper is reachable through a candidate proxy exit.
func (p *CheckPlace) Probe(ctx context.Context, ip netip.Addr) bool {
	_, ok := p.lookupDB(ctx, ip, "ip2location")
	return ok
}

func (p *CheckPlace) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	var mu sync.Mutex
	results := make([]Result, 0, len(p.databases))
	var wg sync.WaitGroup
	for _, db := range p.databases {
		wg.Add(1)
		go func(db string) {
			defer wg.Done()
			result, ok := p.lookupDB(ctx, ip, db)
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(db)
	}
	wg.Wait()
	if len(results) == 0 {
		return Result{}, false
	}
	merged := Result{Source: p.Name()}
	for _, result := range results {
		mergeResultInto(&merged, result)
	}
	return merged, true
}

func (p *CheckPlace) lookupDB(ctx context.Context, ip netip.Addr, db string) (Result, bool) {
	url := p.endpoint + "/" + ip.Unmap().String() + "?db=" + db
	body, ok := fetchJSON(ctx, p.client, url, map[string]string{
		"User-Agent":      checkPlaceUserAgent,
		"Accept":          "application/json,text/plain,*/*",
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !ok {
		return Result{}, false
	}
	switch db {
	case "abuseipdb":
		return parseAbuseIPDB(body)
	case "ip2location":
		return parseIP2Location(body)
	case "ipdata":
		return parseIPData(body)
	case "ipqualityscore":
		return parseIPQS(body)
	case "scamalytics":
		return parseScamalytics(body)
	}
	return Result{}, false
}

func parseAbuseIPDB(body []byte) (Result, bool) {
	var response struct {
		Data struct {
			UsageType            string `json:"usageType"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	return Result{
		Source:      "check.place:abuseipdb",
		CountryCode: response.Data.CountryCode,
		Type:        abuseIPDBUsageType(response.Data.UsageType),
		RiskScore:   float64(response.Data.AbuseConfidenceScore),
		HasScore:    true,
	}, true
}

func abuseIPDBUsageType(usage string) string {
	switch strings.TrimSpace(usage) {
	case "Commercial":
		return TypeBusiness
	case "Data Center/Web Hosting/Transit":
		return TypeHosting
	case "University/College/School":
		return TypeEducation
	case "Government", "Military":
		return TypeGovernment
	case "Library":
		return TypeEducation
	case "Content Delivery Network":
		return TypeCDN
	case "Fixed Line ISP":
		return TypeResidential
	case "Mobile ISP":
		return TypeMobile
	case "Organization", "Search Engine Spider", "Reserved":
		return TypeOther
	}
	return ""
}

func parseIP2Location(body []byte) (Result, bool) {
	var response struct {
		UsageType string `json:"usage_type"`
		AsInfo    struct {
			AsUsageType string `json:"as_usage_type"`
		} `json:"as_info"`
		CountryCode string `json:"country_code"`
		IsProxy     bool   `json:"is_proxy"`
		Proxy       struct {
			IsPublicProxy bool `json:"is_public_proxy"`
			IsWebProxy    bool `json:"is_web_proxy"`
			IsTor         bool `json:"is_tor"`
			IsVPN         bool `json:"is_vpn"`
			IsDataCenter  bool `json:"is_data_center"`
			IsSpammer     bool `json:"is_spammer"`
			IsWebCrawler  bool `json:"is_web_crawler"`
			IsScanner     bool `json:"is_scanner"`
			IsBotnet      bool `json:"is_botnet"`
		} `json:"proxy"`
		FraudScore int `json:"fraud_score"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	result := Result{
		Source:      "check.place:ip2location",
		CountryCode: response.CountryCode,
		Type:        ip2LocationUsageType(response.UsageType),
		Proxy:       response.IsProxy || response.Proxy.IsPublicProxy || response.Proxy.IsWebProxy,
		Tor:         response.Proxy.IsTor,
		VPN:         response.Proxy.IsVPN,
		Datacenter:  response.Proxy.IsDataCenter,
		Abuser:      response.Proxy.IsSpammer,
		Crawler:     response.Proxy.IsWebCrawler || response.Proxy.IsScanner || response.Proxy.IsBotnet,
		RiskScore:   float64(response.FraudScore),
		HasScore:    true,
	}
	if result.Type == "" {
		result.Type = ip2LocationUsageType(response.AsInfo.AsUsageType)
	}
	return result, true
}

func ip2LocationUsageType(code string) string {
	switch strings.TrimSpace(code) {
	case "COM":
		return TypeBusiness
	case "DCH":
		return TypeHosting
	case "EDU":
		return TypeEducation
	case "GOV":
		return TypeGovernment
	case "ORG":
		return TypeOther
	case "MIL":
		return TypeGovernment
	case "LIB":
		return TypeEducation
	case "CDN":
		return TypeCDN
	case "ISP":
		return TypeResidential
	case "MOB":
		return TypeMobile
	case "SES", "RSV":
		return TypeOther
	}
	return ""
}

func parseIPData(body []byte) (Result, bool) {
	var response struct {
		CountryCode string `json:"country_code"`
		Threat      struct {
			IsProxy         bool `json:"is_proxy"`
			IsTor           bool `json:"is_tor"`
			IsDatacenter    bool `json:"is_datacenter"`
			IsThreat        bool `json:"is_threat"`
			IsKnownAbuser   bool `json:"is_known_abuser"`
			IsKnownAttacker bool `json:"is_known_attacker"`
		} `json:"threat"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	return Result{
		Source:      "check.place:ipdata",
		CountryCode: response.CountryCode,
		Proxy:       response.Threat.IsProxy,
		Tor:         response.Threat.IsTor,
		Datacenter:  response.Threat.IsDatacenter,
		Abuser:      response.Threat.IsThreat || response.Threat.IsKnownAbuser || response.Threat.IsKnownAttacker,
	}, true
}

func parseIPQS(body []byte) (Result, bool) {
	var response struct {
		FraudScore  int    `json:"fraud_score"`
		CountryCode string `json:"country_code"`
		Proxy       bool   `json:"proxy"`
		Tor         bool   `json:"tor"`
		VPN         bool   `json:"vpn"`
		RecentAbuse bool   `json:"recent_abuse"`
		BotStatus   bool   `json:"bot_status"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	return Result{
		Source:      "check.place:ipqs",
		CountryCode: response.CountryCode,
		Proxy:       response.Proxy,
		Tor:         response.Tor,
		VPN:         response.VPN,
		Abuser:      response.RecentAbuse,
		Crawler:     response.BotStatus,
		RiskScore:   float64(response.FraudScore),
		HasScore:    true,
	}, true
}

func parseScamalytics(body []byte) (Result, bool) {
	var response struct {
		ExternalDatasources struct {
			MaxmindGeolite2 struct {
				IPCountryCode string `json:"ip_country_code"`
			} `json:"maxmind_geolite2"`
			Firehol struct {
				IsProxy bool `json:"is_proxy"`
			} `json:"firehol"`
			X4bnet struct {
				IsTor                bool `json:"is_tor"`
				IsBlacklistedSpambot bool `json:"is_blacklisted_spambot"`
				IsBotOperamini       bool `json:"is_bot_operamini"`
				IsBotSemrush         bool `json:"is_bot_semrush"`
			} `json:"x4bnet"`
		} `json:"external_datasources"`
		Scamalytics struct {
			ScamalyticsProxy struct {
				IsVPN        bool `json:"is_vpn"`
				IsDatacenter bool `json:"is_datacenter"`
			} `json:"scamalytics_proxy"`
			IsBlacklistedExternal bool `json:"is_blacklisted_external"`
			ScamalyticsScore      int  `json:"scamalytics_score"`
		} `json:"scamalytics"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	return Result{
		Source:      "check.place:scamalytics",
		CountryCode: response.ExternalDatasources.MaxmindGeolite2.IPCountryCode,
		Proxy:       response.ExternalDatasources.Firehol.IsProxy,
		Tor:         response.ExternalDatasources.X4bnet.IsTor,
		VPN:         response.Scamalytics.ScamalyticsProxy.IsVPN,
		Datacenter:  response.Scamalytics.ScamalyticsProxy.IsDatacenter,
		Abuser:      response.Scamalytics.IsBlacklistedExternal,
		Crawler:     response.ExternalDatasources.X4bnet.IsBlacklistedSpambot || response.ExternalDatasources.X4bnet.IsBotOperamini || response.ExternalDatasources.X4bnet.IsBotSemrush,
		RiskScore:   float64(response.Scamalytics.ScamalyticsScore),
		HasScore:    true,
	}, true
}

func mergeResultInto(dst *Result, src Result) {
	dst.Proxy = dst.Proxy || src.Proxy
	dst.VPN = dst.VPN || src.VPN
	dst.Tor = dst.Tor || src.Tor
	dst.Abuser = dst.Abuser || src.Abuser
	dst.Datacenter = dst.Datacenter || src.Datacenter
	dst.Crawler = dst.Crawler || src.Crawler
	if src.HasScore {
		dst.HasScore = true
		if src.RiskScore > dst.RiskScore {
			dst.RiskScore = src.RiskScore
		}
	}
	if dst.ASN == "" && src.ASN != "" {
		dst.ASN = src.ASN
	}
	if dst.Organization == "" && src.Organization != "" {
		dst.Organization = src.Organization
	}
	if dst.ISP == "" && src.ISP != "" {
		dst.ISP = src.ISP
	}
	if dst.CountryCode == "" && src.CountryCode != "" {
		dst.CountryCode = src.CountryCode
	}
	if dst.City == "" && src.City != "" {
		dst.City = src.City
	}
	if dst.Type == "" && src.Type != "" {
		dst.Type = src.Type
	}
}
