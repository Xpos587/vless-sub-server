package ipintel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ProxyCheck queries proxycheck.io for rich reputation data. It rotates
// through multiple *http.Client instances (routed through different proxies)
// so the per-source-IP daily quota is spread across the pool.
type ProxyCheck struct {
	clients  []*http.Client
	timeout  time.Duration
	mu       sync.Mutex
	next     int
	baseURL  string
	recorder func(ProviderOutcome)
}

func (p *ProxyCheck) SetRecorder(recorder func(ProviderOutcome)) {
	if p != nil {
		p.recorder = recorder
	}
}

func NewProxyCheck(clients []*http.Client, timeout time.Duration) *ProxyCheck {
	if len(clients) == 0 {
		return nil
	}
	return newProxyCheckWithURL(clients, timeout, "https://proxycheck.io/v3")
}

func newProxyCheckWithURL(clients []*http.Client, timeout time.Duration, baseURL string) *ProxyCheck {
	if len(clients) == 0 {
		return nil
	}
	return &ProxyCheck{clients: clients, timeout: timeout, baseURL: strings.TrimRight(baseURL, "/")}
}

func (p *ProxyCheck) Name() string { return "proxycheck.io" }

func (p *ProxyCheck) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	result, outcome := p.LookupDetailed(ctx, ip)
	return result, outcome == ProviderSuccess
}

func (p *ProxyCheck) LookupDetailed(ctx context.Context, ip netip.Addr) (Result, ProviderOutcome) {
	p.mu.Lock()
	start := p.next % len(p.clients)
	p.next++
	p.mu.Unlock()
	lastOutcome := ProviderTransport
	for offset := range p.clients {
		client := p.clients[(start+offset)%len(p.clients)]
		result, outcome := p.lookupClient(ctx, client, ip)
		if p.recorder != nil {
			p.recorder(outcome)
		}
		if outcome == ProviderSuccess {
			return result, outcome
		}
		lastOutcome = outcome
		if outcome == ProviderParseError || ctx.Err() != nil {
			break
		}
	}
	return Result{}, lastOutcome
}

func (p *ProxyCheck) lookupClient(ctx context.Context, client *http.Client, ip netip.Addr) (Result, ProviderOutcome) {
	url := p.baseURL + "/" + ip.Unmap().String() + "?vpn=1&asn=1&risk=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, ProviderParseError
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")
	req.Header.Set("Accept", "application/json")

	queryCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req = req.WithContext(queryCtx)
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, ProviderTransport
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return Result{}, ProviderParseError
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(body)), "limit") {
		return Result{}, ProviderQuota
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, ProviderHTTPError
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Result{}, ProviderParseError
	}

	var status string
	if raw, ok := envelope["status"]; ok {
		_ = json.Unmarshal(raw, &status)
	}
	if status == "denied" || status == "error" {
		var message string
		_ = json.Unmarshal(envelope["message"], &message)
		if strings.Contains(strings.ToLower(message), "limit") || strings.Contains(strings.ToLower(message), "quota") {
			return Result{}, ProviderQuota
		}
		return Result{}, ProviderHTTPError
	}

	ipStr := ip.Unmap().String()
	raw, ok := envelope[ipStr]
	if !ok {
		return Result{}, ProviderParseError
	}

	var info struct {
		Network struct {
			ASN          string `json:"asn"`
			Provider     string `json:"provider"`
			Organisation string `json:"organisation"`
			Type         string `json:"type"`
		} `json:"network"`
		Location struct {
			Country string `json:"country_code"`
			City    string `json:"city_name"`
		} `json:"location"`
		Detections struct {
			Proxy       bool    `json:"proxy"`
			VPN         bool    `json:"vpn"`
			Tor         bool    `json:"tor"`
			Hosting     bool    `json:"hosting"`
			Compromised bool    `json:"compromised"`
			Scraper     bool    `json:"scraper"`
			Risk        float64 `json:"risk"`
		} `json:"detections"`
	}

	if err := json.Unmarshal(raw, &info); err != nil {
		return Result{}, ProviderParseError
	}

	result := Result{
		Source:       p.Name(),
		Organization: firstNonEmpty(info.Network.Provider, info.Network.Organisation),
		CountryCode:  strings.ToUpper(info.Location.Country),
		City:         info.Location.City,
		Type:         normalizeProviderType(info.Network.Type),
		Proxy:        info.Detections.Proxy,
		VPN:          info.Detections.VPN,
		Tor:          info.Detections.Tor,
		Abuser:       info.Detections.Compromised,
		Datacenter:   info.Detections.Hosting,
		Crawler:      info.Detections.Scraper,
		RiskScore:    info.Detections.Risk,
		HasScore:     true,
	}
	if info.Network.ASN != "" {
		if !strings.HasPrefix(info.Network.ASN, "AS") {
			result.ASN = "AS" + info.Network.ASN
		} else {
			result.ASN = info.Network.ASN
		}
	}
	return result, ProviderSuccess
}
