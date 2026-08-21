package ipintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProxyCheck queries proxycheck.io for rich reputation data. It rotates
// through multiple *http.Client instances (routed through different proxies)
// so the per-source-IP daily quota is spread across the pool.
type ProxyCheck struct {
	clients []*http.Client
	timeout time.Duration
	mu      sync.Mutex
	next    int
}

func NewProxyCheck(clients []*http.Client, timeout time.Duration) *ProxyCheck {
	if len(clients) == 0 {
		return nil
	}
	return &ProxyCheck{clients: clients, timeout: timeout}
}

func (p *ProxyCheck) Name() string { return "proxycheck.io" }

func (p *ProxyCheck) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	p.mu.Lock()
	client := p.clients[p.next%len(p.clients)]
	p.next++
	p.mu.Unlock()

	url := "https://proxycheck.io/v3/" + ip.Unmap().String() + "?vpn=1&asn=1&risk=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, false
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")
	req.Header.Set("Accept", "application/json")

	queryCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req = req.WithContext(queryCtx)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return Result{}, false
	}
	defer resp.Body.Close()

	var envelope map[string]json.RawMessage
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&envelope); err != nil {
		return Result{}, false
	}

	var status string
	if raw, ok := envelope["status"]; ok {
		_ = json.Unmarshal(raw, &status)
	}
	if status == "denied" || status == "error" {
		return Result{}, false
	}

	ipStr := ip.Unmap().String()
	raw, ok := envelope[ipStr]
	if !ok {
		return Result{}, false
	}

	var info struct {
		ASN          string `json:"asn"`
		Provider     string `json:"provider"`
		Organisation string `json:"organisation"`
		Type         string `json:"type"`
		Country      string `json:"country"`
		Proxy        string `json:"proxy"`
		VPN          string `json:"vpn"`
		Tor          string `json:"tor"`
		Hosting      string `json:"hosting"`
		Risk         string `json:"risk"`
	}

	if err := json.Unmarshal(raw, &info); err != nil {
		return Result{}, false
	}

	result := Result{
		Source:       p.Name(),
		Organization: firstNonEmpty(info.Provider, info.Organisation),
		CountryCode:  strings.ToUpper(info.Country),
		Type:         normalizeProviderType(info.Type),
		Proxy:        toBool(info.Proxy),
		VPN:          toBool(info.VPN),
		Tor:          toBool(info.Tor),
		Datacenter:   toBool(info.Hosting),
	}
	if info.ASN != "" {
		if !strings.HasPrefix(info.ASN, "AS") {
			result.ASN = "AS" + info.ASN
		} else {
			result.ASN = info.ASN
		}
	}
	if risk, ok := parseRiskScore(info.Risk); ok {
		result.RiskScore = risk
		result.HasScore = true
	}
	return result, true
}

func toBool(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "yes")
}

func parseRiskScore(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}
