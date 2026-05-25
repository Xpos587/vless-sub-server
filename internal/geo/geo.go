package geo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type GeoInfo struct {
	CountryCode string
	City        string
	ISP         string
	IP          string
}

// ipwho.is response
type IPWhoisResponse struct {
	IP          string `json:"ip"`
	Success     bool   `json:"success"`
	CountryCode string `json:"country_code"`
	City         string `json:"city"`
	Connection  struct {
		ISP string `json:"isp"`
	} `json:"connection"`
}

// Cloudflare trace parsed result
type CFTraceResult struct {
	IP       string
	Location string // 2-letter country code
}

// ip-api.com batch response entry
type IPAPIEntry struct {
	Status      string `json:"status"`
	Query       string `json:"query"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

// BatchGeoLookup queries ip-api.com/batch for geo info on multiple IPs.
func BatchGeoLookup(ips []string, timeout time.Duration) map[string]*GeoInfo {
	result := make(map[string]*GeoInfo)
	if len(ips) == 0 {
		return result
	}

	payload, _ := json.Marshal(ips)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(
		"http://ip-api.com/batch?fields=status,message,query,countryCode,city,isp",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	var entries []IPAPIEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return result
	}

	for _, e := range entries {
		if e.Status == "success" && e.CountryCode != "" {
			result[e.Query] = &GeoInfo{
				CountryCode: e.CountryCode,
				City:        e.City,
				ISP:         e.ISP,
				IP:          e.Query,
			}
		}
	}

	return result
}

// GeoInfoFromExitIP creates a GeoInfo from an exit IP using ipwho.is single lookup.
func GeoInfoFromExitIP(ip string) *GeoInfo {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ipwho.is/%s", ip))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var ipResp IPWhoisResponse
	if err := json.Unmarshal(body, &ipResp); err != nil || !ipResp.Success {
		return nil
	}

	return &GeoInfo{
		CountryCode: ipResp.CountryCode,
		City:        ipResp.City,
		ISP:         ipResp.Connection.ISP,
		IP:          ipResp.IP,
	}
}