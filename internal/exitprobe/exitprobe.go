package exitprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"

	"github.com/xtls/xray-core/common/session"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/sync/errgroup"
)

type ExitProbeResult struct {
	ExitIP   string
	ExitLoc  string
	GeoInfo  *geo.GeoInfo
	XrayOK   bool
}

type ExitProber struct {
	cfg       *config.Config
	instance  *core.Instance
	proxyTags []string // proxy index -> outbound tag
	transport *http.Transport
	mu        sync.Mutex
}

func NewExitProber(cfg *config.Config) *ExitProber {
	return &ExitProber{
		cfg:       cfg,
		proxyTags: nil,
		transport: &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			DialContext:           (&net.Dialer{Timeout: cfg.ExitProbeTimeout, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   cfg.ExitProbeTimeout,
			ResponseHeaderTimeout:  cfg.ExitProbeTimeout,
		},
	}
}

func (ep *ExitProber) StartWithProxies(records []parse.ProxyRecord) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.instance != nil {
		ep.instance.Close()
		ep.instance = nil
	}

	configJSON := buildOutboundOnlyConfig(records)
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
	ep.proxyTags = make([]string, len(records))
	for i := range records {
		ep.proxyTags[i] = fmt.Sprintf("proxy_%d_out", i)
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
	var mu sync.Mutex
	maxConcurrent := ep.cfg.MaxConcurrent
	if len(records) < maxConcurrent {
		maxConcurrent = len(records)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrent)

	for i, rec := range records {
		i, rec := i, rec
		g.Go(func() error {
			result := ep.probeSingle(ctx, i, rec)
			mu.Lock()
			results[i] = result
			mu.Unlock()
			return nil
		})
	}
	g.Wait()

	// Batch geo lookup for all successful exit IPs
	ep.batchGeoLookup(results)
	return results
}

func (ep *ExitProber) probeSingle(ctx context.Context, idx int, record parse.ProxyRecord) *ExitProbeResult {
	select {
	case <-ctx.Done():
		return &ExitProbeResult{XrayOK: false}
	default:
	}

	if idx >= len(ep.proxyTags) {
		return &ExitProbeResult{XrayOK: false}
	}
	outboundTag := ep.proxyTags[idx]

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)
			dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
			return core.Dial(ctx, ep.instance, dest)
		},
		TLSHandshakeTimeout:   ep.cfg.ExitProbeTimeout,
		ResponseHeaderTimeout: ep.cfg.ExitProbeTimeout,
		IdleConnTimeout:        90 * time.Second,
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/", nil)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}

	var ipResp geo.IPWhoisResponse
	if err := json.Unmarshal(body, &ipResp); err != nil || !ipResp.Success {
		return ep.probeCFTrace(ctx, transport)
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

func (ep *ExitProber) probeCFTrace(ctx context.Context, transport *http.Transport) *ExitProbeResult {
	client := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return &ExitProbeResult{XrayOK: false}
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

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

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       map[string]any  `json:"settings"`
	StreamSettings map[string]any  `json:"streamSettings,omitempty"`
}

type xrayDialConfig struct {
	Log       map[string]any    `json:"log"`
	Outbounds []xrayOutbound    `json:"outbounds"`
}

func buildOutboundOnlyConfig(records []parse.ProxyRecord) []byte {
	cfg := xrayDialConfig{
		Log: map[string]any{"loglevel": "warning"},
	}

	cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
		Tag:      "direct",
		Protocol: "freedom",
		Settings: map[string]any{},
	})

	for i, rec := range records {
		outTag := fmt.Sprintf("proxy_%d_out", i)
		ob := buildOutbound(rec, outTag)
		cfg.Outbounds = append(cfg.Outbounds, ob)
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
							"encryption": vlessEncryption(rec),
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
							"security": vmessSecurity(rec),
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
		ob.Protocol = "shadowsocks"
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

	case parse.Hysteria2:
		ob.Protocol = "hysteria"
		ob.Settings = map[string]any{
			"address": rec.Host,
			"port":    rec.Port,
			"version": 2,
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
		if rec.Protocol == parse.Hysteria2 {
			ss["network"] = "hysteria"
		} else {
			ss["network"] = "tcp"
		}
	}
	if ss["security"] == nil {
		if rec.Protocol == parse.Hysteria2 {
			ss["security"] = "tls"
		} else {
			ss["security"] = "none"
		}
	}

	network := ss["network"].(string)
	security := ss["security"].(string)

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
		if v, ok := rec.QueryParams["spx"]; ok {
			rs["spiderX"] = v
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
		if v, ok := rec.QueryParams["alpn"]; ok && v != "" {
			ts["alpn"] = strings.Split(v, ",")
		}
		ss["tlsSettings"] = ts
	}

	switch network {
	case "tcp":
		if rec.QueryParams["headerType"] == "http" {
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http"},
			}
		}
	case "ws":
		ws := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			ws["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			ws["host"] = v
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
	case "kcp":
		ks := map[string]any{}
		if v, ok := rec.QueryParams["seed"]; ok {
			ks["seed"] = v
		}
		if rec.QueryParams["headerType"] == "http" {
			ks["header"] = map[string]any{"type": "http"}
		}
		ss["kcpSettings"] = ks
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
	case "hysteria":
		hy := map[string]any{
			"version": 2,
			"auth":     rec.UUIDOrPassword,
		}
		ss["hysteriaSettings"] = hy
	}

	return ss
}

func vlessEncryption(rec parse.ProxyRecord) string {
	if enc, ok := rec.QueryParams["encryption"]; ok && enc != "" && enc != "none" {
		return enc
	}
	return "none"
}

func vmessSecurity(rec parse.ProxyRecord) string {
	if scy, ok := rec.QueryParams["scy"]; ok && scy != "" {
		return scy
	}
	return "auto"
}