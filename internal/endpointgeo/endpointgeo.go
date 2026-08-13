// Package endpointgeo resolves metadata for configured proxy endpoints.
package endpointgeo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/geo"
)

const lookupURL = "https://ipwho.is/"

type lookupResponse struct {
	Success     bool   `json:"success"`
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Connection  struct {
		ISP string `json:"isp"`
		Org string `json:"org"`
	} `json:"connection"`
}

func parse(body []byte) (*geo.GeoInfo, bool) {
	var response lookupResponse
	if json.Unmarshal(body, &response) != nil || !response.Success {
		return nil, false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(response.IP))
	code := strings.ToUpper(strings.TrimSpace(response.CountryCode))
	if err != nil || len(code) != 2 {
		return nil, false
	}
	city := strings.TrimSpace(response.City)
	if city == "" {
		city = strings.TrimSpace(response.Region)
	}
	isp := strings.TrimSpace(response.Connection.ISP)
	if isp == "" {
		isp = strings.TrimSpace(response.Connection.Org)
	}
	return &geo.GeoInfo{CountryCode: code, City: city, ISP: isp, IP: ip.Unmap().String()}, true
}

// LookupAll returns independently resolved metadata keyed by endpoint IP.
func LookupAll(ctx context.Context, ips []string, maxConcurrent int, timeout time.Duration) map[string]*geo.GeoInfo {
	result := make(map[string]*geo.GeoInfo, len(ips))
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	client := &http.Client{Timeout: timeout}
	sem := make(chan struct{}, maxConcurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, rawIP := range ips {
		ip, err := netip.ParseAddr(rawIP)
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL+ip.String(), nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if err != nil {
				return
			}
			info, ok := parse(body)
			if !ok {
				return
			}
			mu.Lock()
			result[ip.String()] = info
			mu.Unlock()
		}()
	}
	wg.Wait()
	return result
}
