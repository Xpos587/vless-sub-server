package exitprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

type ExitProbeResult struct {
	ExitIP   string
	ExitLoc  string
	GeoInfo  *geo.GeoInfo
	XrayOK   bool
}

type ExitProber struct {
	cfg        *config.Config
	instance   *core.Instance
	socksPorts map[int]int // proxy index -> socks port
	mu         sync.Mutex
}

func NewExitProber(cfg *config.Config) *ExitProber {
	return &ExitProber{
		cfg:        cfg,
		socksPorts: make(map[int]int),
	}
}

func (ep *ExitProber) StartWithProxies(records []parse.ProxyRecord) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.instance != nil {
		ep.instance.Close()
		ep.instance = nil
	}

	configJSON := buildCheckConfig(records, ep.cfg.SocksStartPort)
	xrayConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("decode xray config: %w", err)
	}
	coreConfig, err := xrayConfig.Build()
	if err != nil {
		return fmt.Errorf("build xray config: %w", err)
	}

	instance, err := core.New(coreConfig)
	if err != nil {
		return fmt.Errorf("create xray instance: %w", err)
	}
	if err := instance.Start(); err != nil {
		return fmt.Errorf("start xray instance: %w", err)
	}

	ep.instance = instance
	for i := range records {
		ep.socksPorts[i] = ep.cfg.SocksStartPort + i
	}

	return nil
}

func (ep *ExitProber) Stop() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.instance != nil {
		ep.instance.Close()
		ep.instance = nil
	}
}

func (ep *ExitProber) ProbeAll(ctx context.Context, records []parse.ProxyRecord) map[int]*ExitProbeResult {
	results := make(map[int]*ExitProbeResult, len(records))
	sem := make(chan struct{}, ep.cfg.MaxConcurrent)
	var wg sync.WaitGroup

	for i, rec := range records {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, record parse.ProxyRecord) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = ep.probeSingle(ctx, idx, record)
		}(i, rec)
	}
	wg.Wait()

	// Batch geo lookup for all successful exit IPs
	ep.batchGeoLookup(results)
	return results
}

func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
	port, ok := ep.socksPorts[idx]
	if !ok {
		return &ExitProbeResult{XrayOK: false}
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: ep.cfg.ExitProbeTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			DialContext:           (&net.Dialer{Timeout: ep.cfg.ExitProbeTimeout}).DialContext,
			TLSHandshakeTimeout:  ep.cfg.ExitProbeTimeout,
			ResponseHeaderTimeout: ep.cfg.ExitProbeTimeout,
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/", nil)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}

	var ipResp geo.IPWhoisResponse
	if err := json.Unmarshal(body, &ipResp); err != nil || !ipResp.Success {
		// Try CF trace as fallback
		return ep.probeCFTrace(ctx, client)
	}

	return &ExitProbeResult{
		ExitIP:  ipResp.IP,
		ExitLoc: ipResp.CountryCode,
		XrayOK:  true,
		GeoInfo: &geo.GeoInfo{
			CountryCode: ipResp.CountryCode,
			City:        ipResp.City,
			ISP:         ipResp.Connection.ISP,
			IP:          ipResp.IP,
		},
	}
}

func (ep *ExitProber) probeCFTrace(ctx context.Context, client *http.Client) *ExitProbeResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}

	result := &ExitProbeResult{XrayOK: true}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ip=") {
			result.ExitIP = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			result.ExitLoc = strings.TrimPrefix(line, "loc=")
		}
	}
	if result.ExitIP == "" {
		return &ExitProbeResult{XrayOK: false}
	}
	return result
}

func (ep *ExitProber) batchGeoLookup(results map[int]*ExitProbeResult) {
	// Collect IPs that need geo lookup (those without geo from ipwho.is)
	var ips []string
	ipToIdx := map[string][]int{}
	for idx, r := range results {
		if r.XrayOK && r.GeoInfo == nil && r.ExitIP != "" {
			if _, exists := ipToIdx[r.ExitIP]; !exists {
				ips = append(ips, r.ExitIP)
			}
			ipToIdx[r.ExitIP] = append(ipToIdx[r.ExitIP], idx)
		}
	}

	if len(ips) == 0 {
		return
	}

	// ip-api.com batch
	payload, _ := json.Marshal(ips)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("http://ip-api.com/batch?fields=status,message,query,countryCode,city,isp",
		"application/json", bytes.NewReader(payload))
	if err != nil {
		// Fallback: use CF trace loc only
		for _, idx := range ipToIdx {
			for _, i := range idx {
				if results[i] != nil && results[i].XrayOK {
					results[i].GeoInfo = &geo.GeoInfo{
						CountryCode: results[i].ExitLoc,
						City:        results[i].ExitLoc,
						ISP:         "Unknown",
						IP:          results[i].ExitIP,
					}
				}
			}
		}
		return
	}
	defer resp.Body.Close()

	var entries []struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return
	}

	for _, e := range entries {
		if e.Status == "success" && e.CountryCode != "" {
			info := &geo.GeoInfo{
				CountryCode: e.CountryCode,
				City:        e.City,
				ISP:         e.ISP,
				IP:          e.Query,
			}
			for _, idx := range ipToIdx[e.Query] {
				results[idx].GeoInfo = info
			}
		}
	}
}

type xrayInbound struct {
	Tag      string `json:"tag"`
	Port     int    `json:"port"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
	Settings struct {
		Auth string `json:"auth"`
		UDP  bool   `json:"udp"`
	} `json:"settings"`
}

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       map[string]any  `json:"settings"`
	StreamSettings map[string]any  `json:"streamSettings,omitempty"`
}

type xrayRoutingRule struct {
	Type        string   `json:"type"`
	InboundTag  []string `json:"inboundTag"`
	OutboundTag string   `json:"outboundTag"`
}

type xrayConfig struct {
	Log       map[string]any    `json:"log"`
	Inbounds  []xrayInbound     `json:"inbounds"`
	Outbounds []xrayOutbound    `json:"outbounds"`
	Routing   struct {
		Rules []xrayRoutingRule `json:"rules"`
	} `json:"routing"`
}

func buildCheckConfig(records []parse.ProxyRecord, startPort int) []byte {

	cfg := xrayConfig{
		Log: map[string]any{"loglevel": "warning"},
	}

	// Direct outbound
	cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
		Tag:      "direct",
		Protocol: "freedom",
		Settings: map[string]any{},
	})

	for i, rec := range records {
		inTag := fmt.Sprintf("proxy_%d_in", i)
		outTag := fmt.Sprintf("proxy_%d_out", i)

		ib := xrayInbound{
			Tag:      inTag,
			Port:     startPort + i,
			Listen:   "127.0.0.1",
			Protocol: "socks",
		}
		ib.Settings.Auth = "noauth"
		ib.Settings.UDP = false
		cfg.Inbounds = append(cfg.Inbounds, ib)

		ob := buildOutbound(rec, outTag)
		cfg.Outbounds = append(cfg.Outbounds, ob)

		cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRoutingRule{
			Type:        "field",
			InboundTag:  []string{inTag},
			OutboundTag: outTag,
		})
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	return data
}

func buildOutbound(rec parse.ProxyRecord, tag string) xrayOutbound {
	ob := xrayOutbound{
		Tag:      tag,
		Protocol: string(rec.Protocol),
		Settings: make(map[string]any),
	}

	switch rec.Protocol {
	case parse.VLESS:
		ob.Settings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []map[string]any{
						{
							"id":         rec.UUIDOrPassword,
							"encryption": "none",
						},
					},
				},
			},
		}
		if flow, ok := rec.QueryParams["flow"]; ok && flow != "" {
			ob.Settings["vnext"].([]map[string]any)[0]["users"].([]map[string]any)[0]["flow"] = flow
		}

	case parse.VMess:
		ob.Settings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []map[string]any{
						{
							"id":       rec.UUIDOrPassword,
							"alterId":   0,
							"security": rec.QueryParams["security"],
						},
					},
				},
			},
		}

	case parse.Trojan:
		ob.Settings = map[string]any{
			"servers": []map[string]any{
				{
					"address":  rec.Host,
					"port":     rec.Port,
					"password": rec.UUIDOrPassword,
				},
			},
		}

	case parse.SS:
		method := rec.QueryParams["method"]
		if method == "" {
			method = "aes-256-gcm"
		}
		ob.Settings = map[string]any{
			"servers": []map[string]any{
				{
					"address":  rec.Host,
					"port":     rec.Port,
					"method":   method,
					"password": rec.UUIDOrPassword,
				},
			},
		}
	}

	ob.StreamSettings = buildStreamSettings(rec)
	return ob
}

func buildStreamSettings(rec parse.ProxyRecord) map[string]any {
	ss := map[string]any{
		"network":  rec.QueryParams["type"],
		"security": rec.QueryParams["security"],
	}

	if ss["network"] == nil {
		ss["network"] = "tcp"
	}
	if ss["security"] == nil {
		ss["security"] = "none"
	}

	network := ss["network"].(string)
	security := ss["security"].(string)

	// Reality settings
	if security == "reality" {
		rs := map[string]any{}
		if v, ok := rec.QueryParams["sni"]; ok {
			rs["serverName"] = v
		}
		if v, ok := rec.QueryParams["fp"]; ok {
			rs["fingerprint"] = v
		}
		if v, ok := rec.QueryParams["pbk"]; ok {
			rs["publicKey"] = v
		}
		if v, ok := rec.QueryParams["sid"]; ok {
			rs["shortId"] = v
		}
		if v, ok := rec.QueryParams["flow"]; ok {
			rs["flow"] = v
		}
		ss["realitySettings"] = rs
	} else if security == "tls" {
		ts := map[string]any{}
		if v, ok := rec.QueryParams["sni"]; ok {
			ts["serverName"] = v
		}
		if v, ok := rec.QueryParams["fp"]; ok {
			ts["fingerprint"] = v
		}
		if rec.QueryParams["insecure"] == "1" {
			ts["allowInsecure"] = true
		}
		ss["tlsSettings"] = ts
	}

	// Transport settings
	switch network {
	case "ws":
		ws := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			ws["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			ws["headers"] = map[string]any{"Host": v}
		}
		ss["wsSettings"] = ws
	case "grpc":
		gs := map[string]any{}
		if v, ok := rec.QueryParams["serviceName"]; ok {
			gs["serviceName"] = v
		}
		if v, ok := rec.QueryParams["mode"]; ok {
			gs["multiMode"] = (v == "multi")
		}
		ss["grpcSettings"] = gs
	case "httpupgrade":
		hu := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			hu["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			hu["host"] = v
		}
		ss["httpupgradeSettings"] = hu
	case "xhttp":
		xh := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			xh["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			xh["host"] = v
		}
		if v, ok := rec.QueryParams["mode"]; ok {
			xh["mode"] = v
		}
		ss["xhttpSettings"] = xh
	}

	return ss
}