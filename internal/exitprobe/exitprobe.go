package exitprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/quality"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"golang.org/x/sync/errgroup"
)

const (
	geoAPIURL       = "https://ipwho.is/"
	healthAPIURL    = "https://speed.cloudflare.com/__down?bytes=0"
	bandwidthAPIURL = "https://speed.cloudflare.com/__down?bytes="
)

type ExitProbeResult struct {
	ExitIP  string
	ExitLoc string
	GeoInfo *geo.GeoInfo
	XrayOK  bool
	Metrics quality.Metrics
}

func aggregateHealthSamples(samples []time.Duration, requested int, geoOK bool) quality.Metrics {
	return quality.Aggregate(samples, requested-len(samples), requested, geoOK)
}

type ExitProber struct {
	cfg       *config.Config
	instance  *core.Instance
	proxyTags []string
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
			ResponseHeaderTimeout: cfg.ExitProbeTimeout,
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

	body, geoOK := ep.request(ctx, outboundTag, geoAPIURL, ep.cfg.ExitProbeTimeout)
	var ipResp geo.IPWhoisResponse
	geoOK = geoOK && json.Unmarshal(body, &ipResp) == nil && ipResp.Success && ipResp.IP != ""

	sampleCount := ep.cfg.ProbeSampleCount
	if sampleCount == 0 {
		sampleCount = 5
	}
	sampleTimeout := ep.cfg.ProbeSampleTimeout
	if sampleTimeout == 0 {
		sampleTimeout = 5 * time.Second
	}
	var samples []time.Duration
	for i := 0; i < sampleCount; i++ {
		start := time.Now()
		body, ok := ep.request(ctx, outboundTag, healthAPIURL, sampleTimeout)
		if ok && len(body) == 0 {
			samples = append(samples, time.Since(start))
		}
		if i+1 < sampleCount && ep.cfg.ProbeSampleGap > 0 {
			select {
			case <-ctx.Done():
				return &ExitProbeResult{Metrics: aggregateHealthSamples(samples, sampleCount, geoOK)}
			case <-time.After(ep.cfg.ProbeSampleGap):
			}
		}
	}
	metrics := aggregateHealthSamples(samples, sampleCount, geoOK)
	if !metrics.InternetReachable {
		return &ExitProbeResult{Metrics: metrics}
	}

	city := ipResp.City
	if city == "" {
		city = ipResp.Region
	}
	isp := ipResp.Connection.ISP
	if isp == "" {
		isp = ipResp.Connection.Org
	}

	return &ExitProbeResult{
		ExitIP:  ipResp.IP,
		ExitLoc: ipResp.CountryCode,
		XrayOK:  true,
		Metrics: metrics,
		GeoInfo: &geo.GeoInfo{
			CountryCode: ipResp.CountryCode,
			City:        city,
			ISP:         isp,
			IP:          ipResp.IP,
		},
	}
}

func (ep *ExitProber) request(ctx context.Context, outboundTag, target string, timeout time.Duration) ([]byte, bool) {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		return core.Dial(ctx, ep.instance, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout}
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "vless-sub-server/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, err == nil
}

// ProbeBandwidth measures selected records only; callers schedule them before any bytes are downloaded.
func (ep *ExitProber) ProbeBandwidth(ctx context.Context, indices []int) map[int]float64 {
	results := make(map[int]float64, len(indices))
	if !ep.cfg.BandwidthEnabled {
		return results
	}
	limit := make(chan struct{}, 2)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, index := range indices {
		if index < 0 || index >= len(ep.proxyTags) {
			continue
		}
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()
			mbps := ep.bandwidth(ctx, ep.proxyTags[index])
			if mbps > 0 {
				mu.Lock()
				results[index] = mbps
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return results
}

func (ep *ExitProber) bandwidth(ctx context.Context, outboundTag string) float64 {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx = session.SetForcedOutboundTagToContext(ctx, outboundTag)
		host, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)
		return core.Dial(ctx, ep.instance, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port)))
	}, ResponseHeaderTimeout: ep.cfg.BandwidthTimeout}
	client := &http.Client{Transport: transport, Timeout: ep.cfg.BandwidthTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bandwidthAPIURL+strconv.FormatInt(ep.cfg.BandwidthBytes, 10), nil)
	if err != nil {
		return 0
	}
	var firstByte time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte = time.Now() }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength != ep.cfg.BandwidthBytes {
		return 0
	}
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, ep.cfg.BandwidthBytes+1))
	if err != nil || n != ep.cfg.BandwidthBytes {
		return 0
	}
	if firstByte.IsZero() {
		return 0
	}
	seconds := time.Since(firstByte).Seconds()
	if seconds <= 0 {
		return 0
	}
	return float64(n*8) / seconds / 1e6
}

type xrayOutbound struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings,omitempty"`
}

type xrayDialConfig struct {
	Log       map[string]any `json:"log"`
	Outbounds []xrayOutbound `json:"outbounds"`
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
		alterId := 0
		if v, ok := rec.QueryParams["alterId"]; ok && v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				alterId = n
			}
		}
		ob.Settings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []map[string]any{
						{
							"id":       rec.UUIDOrPassword,
							"security": vmessSecurity(rec),
							"alterId":  alterId,
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
	network := rec.QueryParams["type"]
	if network == "" {
		if rec.Protocol == parse.Hysteria2 {
			network = "hysteria"
		} else {
			network = "tcp"
		}
	}
	security := rec.QueryParams["security"]
	if security == "" {
		if rec.Protocol == parse.Hysteria2 {
			security = "tls"
		} else {
			security = "none"
		}
	}
	ss := map[string]any{
		"network":  network,
		"security": security,
	}

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
			"auth":    rec.UUIDOrPassword,
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
