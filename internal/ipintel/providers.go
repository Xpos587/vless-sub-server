package ipintel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// DefaultProviders returns the no-key public providers that are reachable from
// a datacenter. check.place/scamalytics are intentionally absent: Cloudflare
// blocks server IPs; add them later through a residential proxy dialer.
func DefaultProviders(timeout time.Duration) []Provider {
	return []Provider{
		newIPAPIIS(timeout),
		newIPinfoDemo(timeout),
		newIPAPI(timeout),
		newIPSB(timeout),
	}
}

func fetchJSON(ctx context.Context, client *http.Client, url string, headers map[string]string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false
	}
	return body, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeProviderType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "hosting", "datacenter", "server":
		return TypeHosting
	case "mobile":
		return TypeMobile
	case "business", "commercial":
		return TypeBusiness
	case "education", "school", "university":
		return TypeEducation
	case "government":
		return TypeGovernment
	case "cdn":
		return TypeCDN
	case "isp", "residential":
		return TypeResidential
	case "":
		return ""
	default:
		return TypeOther
	}
}

// parseScorePercent parses "0.0039 (Low)" into 0.39.
func parseScorePercent(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if idx := strings.IndexByte(raw, ' '); idx > 0 {
		raw = raw[:idx]
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return value * 100, true
}

func asnString(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.IndexByte(raw, ' '); idx > 0 {
		raw = raw[:idx]
	}
	if !strings.HasPrefix(raw, "AS") {
		return "AS" + raw
	}
	return raw
}

// ipapi.is

type ipapiIS struct {
	client   *http.Client
	endpoint string
}

func newIPAPIIS(timeout time.Duration) *ipapiIS {
	return &ipapiIS{client: &http.Client{Timeout: timeout}, endpoint: "https://api.ipapi.is"}
}

func (p *ipapiIS) Name() string { return "ipapi.is" }

func (p *ipapiIS) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	body, ok := fetchJSON(ctx, p.client, p.endpoint+"/?q="+ip.Unmap().String(), map[string]string{"Origin": "https://ipapi.is"})
	if !ok {
		return Result{}, false
	}
	var response struct {
		IsDatacenter bool `json:"is_datacenter"`
		IsTor        bool `json:"is_tor"`
		IsProxy      bool `json:"is_proxy"`
		IsVPN        bool `json:"is_vpn"`
		IsAbuser     bool `json:"is_abuser"`
		IsCrawler    bool `json:"is_crawler"`
		ASN          struct {
			ASN  int    `json:"asn"`
			Org  string `json:"org"`
			Descr string `json:"descr"`
			Type string `json:"type"`
		} `json:"asn"`
		Company struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			AbuserScore string `json:"abuser_score"`
		} `json:"company"`
		Location struct {
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
		} `json:"location"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	result := Result{
		Source:       p.Name(),
		Organization: firstNonEmpty(response.ASN.Org, response.Company.Name, response.ASN.Descr),
		CountryCode:  response.Location.CountryCode,
		City:         response.Location.City,
		Type:         normalizeProviderType(firstNonEmpty(response.ASN.Type, response.Company.Type)),
		Proxy:        response.IsProxy,
		VPN:          response.IsVPN,
		Tor:          response.IsTor,
		Abuser:       response.IsAbuser,
		Datacenter:   response.IsDatacenter,
		Crawler:      response.IsCrawler,
	}
	if response.ASN.ASN != 0 {
		result.ASN = "AS" + strconv.Itoa(response.ASN.ASN)
	}
	if score, ok := parseScorePercent(response.Company.AbuserScore); ok {
		result.RiskScore = score
		result.HasScore = true
	}
	return result, true
}

// ipinfo.io widget/demo

type ipinfoDemo struct {
	client   *http.Client
	endpoint string
}

func newIPinfoDemo(timeout time.Duration) *ipinfoDemo {
	return &ipinfoDemo{client: &http.Client{Timeout: timeout}, endpoint: "https://ipinfo.io/widget/demo"}
}

func (p *ipinfoDemo) Name() string { return "ipinfo" }

func (p *ipinfoDemo) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	body, ok := fetchJSON(ctx, p.client, p.endpoint+"/"+ip.Unmap().String(), nil)
	if !ok {
		return Result{}, false
	}
	var response struct {
		Data struct {
			City    string `json:"city"`
			Country string `json:"country"`
			Org     string `json:"org"`
			ASN     struct {
				ASN  string `json:"asn"`
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"asn"`
			Company struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"company"`
			Privacy struct {
				VPN     bool `json:"vpn"`
				Proxy   bool `json:"proxy"`
				Tor     bool `json:"tor"`
				Hosting bool `json:"hosting"`
			} `json:"privacy"`
			IsMobile   bool `json:"is_mobile"`
			IsHosting  bool `json:"is_hosting"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	data := response.Data
	result := Result{
		Source:       p.Name(),
		ASN:          asnString(data.ASN.ASN),
		Organization: firstNonEmpty(data.ASN.Name, data.Company.Name),
		ISP:          firstNonEmpty(data.Org, data.ASN.Name),
		CountryCode:  data.Country,
		City:         data.City,
		Type:         normalizeProviderType(firstNonEmpty(data.ASN.Type, data.Company.Type)),
		Proxy:        data.Privacy.Proxy,
		VPN:          data.Privacy.VPN,
		Tor:          data.Privacy.Tor,
		Datacenter:   data.Privacy.Hosting || data.IsHosting,
	}
	if data.IsMobile {
		result.Type = TypeMobile
	}
	return result, true
}

// ip-api.com

type ipAPI struct {
	client   *http.Client
	endpoint string
	limiter  *rate.Limiter
}

func newIPAPI(timeout time.Duration) *ipAPI {
	return &ipAPI{
		client:   &http.Client{Timeout: timeout},
		endpoint: "http://ip-api.com/json",
		limiter:  rate.NewLimiter(rate.Every(time.Minute/45), 1),
	}
}

func (p *ipAPI) Name() string { return "ip-api" }

func (p *ipAPI) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	if err := p.limiter.Wait(ctx); err != nil {
		return Result{}, false
	}
	fields := "status,message,countryCode,city,isp,org,as,asname,mobile,proxy,hosting"
	body, ok := fetchJSON(ctx, p.client, p.endpoint+"/"+ip.Unmap().String()+"?fields="+fields, nil)
	if !ok {
		return Result{}, false
	}
	var response struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Mobile      bool   `json:"mobile"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
	}
	if json.Unmarshal(body, &response) != nil || response.Status != "success" {
		return Result{}, false
	}
	result := Result{
		Source:       p.Name(),
		ASN:          asnString(response.AS),
		Organization: firstNonEmpty(response.Org, response.ISP),
		ISP:          firstNonEmpty(response.ISP, response.Org),
		CountryCode:  response.CountryCode,
		City:         response.City,
		Proxy:        response.Proxy,
		Datacenter:   response.Hosting,
	}
	if response.Hosting {
		result.Type = TypeHosting
	} else if response.Mobile {
		result.Type = TypeMobile
	}
	return result, true
}

// ip.sb

type ipSB struct {
	client   *http.Client
	endpoint string
}

func newIPSB(timeout time.Duration) *ipSB {
	return &ipSB{client: &http.Client{Timeout: timeout}, endpoint: "https://api.ip.sb/geoip"}
}

func (p *ipSB) Name() string { return "ip.sb" }

func (p *ipSB) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	body, ok := fetchJSON(ctx, p.client, p.endpoint+"/"+ip.Unmap().String(), nil)
	if !ok {
		return Result{}, false
	}
	var response struct {
		ASN             int    `json:"asn"`
		ISP             string `json:"isp"`
		Organization    string `json:"organization"`
		CountryCode     string `json:"country_code"`
		City            string `json:"city"`
		Region          string `json:"region"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Result{}, false
	}
	return Result{
		Source:       p.Name(),
		ASN:          "AS" + strconv.Itoa(response.ASN),
		Organization: firstNonEmpty(response.Organization, response.ISP),
		ISP:          firstNonEmpty(response.ISP, response.Organization),
		CountryCode:  response.CountryCode,
		City:         response.City,
	}, true
}
