package fetch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"golang.org/x/sync/errgroup"
)

var fetchTransport = &http.Transport{
	MaxIdleConns:        10,
	MaxIdleConnsPerHost: 5,
	IdleConnTimeout:     30 * time.Second,
}

type FetchResult struct {
	URL    string
	Status string // "ok" or "error"
	Lines  []string
	Error  string
}

func FetchSubscriptions(ctx context.Context, urls []string, timeout time.Duration) []FetchResult {
	results := make([]FetchResult, len(urls))
	g, _ := errgroup.WithContext(ctx)
	g.SetLimit(len(urls)) // all URLs in parallel — typically 2-5

	for i, u := range urls {
		i, u := i, u
		g.Go(func() error {
			results[i] = fetchSingle(ctx, u, timeout)
			return nil // best-effort: collect all results regardless
		})
	}
	g.Wait()
	return results
}

func fetchSingle(ctx context.Context, url string, timeout time.Duration) FetchResult {
	client := &http.Client{Timeout: timeout, Transport: fetchTransport}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return FetchResult{URL: url, Status: "error", Error: err.Error()}
	}
	for k, v := range config.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[fetch] %s: %v", url, err)
		return FetchResult{URL: url, Status: "error", Error: err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("[fetch] %s: HTTP %d", url, resp.StatusCode)
		return FetchResult{URL: url, Status: "error", Error: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[fetch] %s: read body: %v", url, err)
		return FetchResult{URL: url, Status: "error", Error: err.Error()}
	}

	lines := decodeSubscription(string(body))
	if len(lines) == 0 {
		log.Printf("[fetch] %s: empty response (body=%d bytes)", url, len(body))
		return FetchResult{URL: url, Status: "error", Error: "empty response"}
	}
	log.Printf("[fetch] %s: ok, %d lines", url, len(lines))
	return FetchResult{URL: url, Status: "ok", Lines: lines}
}

func decodeSubscription(raw string) []string {
	trimmed := strings.TrimSpace(raw)

	// Try sing-box JSON
	var parsed json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
		if urls := extractSingboxURLs(parsed); len(urls) > 0 {
			return urls
		}
	}

	// Try base64
	normalized := strings.ReplaceAll(trimmed, "-", "+")
	normalized = strings.ReplaceAll(normalized, "_", "/")
	for len(normalized)%4 != 0 {
		normalized += "="
	}
	if decoded, err := base64.StdEncoding.DecodeString(normalized); err == nil {
		// Might be sing-box JSON inside base64
		var inner json.RawMessage
		if err := json.Unmarshal(decoded, &inner); err == nil {
			if urls := extractSingboxURLs(inner); len(urls) > 0 {
				return urls
			}
		}
		lines := splitNonEmpty(string(decoded))
		if hasProxyScheme(lines) {
			return lines
		}
	}

	return splitNonEmpty(trimmed)
}

func splitNonEmpty(s string) []string {
	var result []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

func hasProxyScheme(lines []string) bool {
	for _, l := range lines {
		for _, s := range []string{"vless://", "vmess://", "trojan://", "ss://"} {
			if strings.HasPrefix(l, s) {
				return true
			}
		}
	}
	return false
}

// singboxOutboundToUrl converts a sing-box outbound to a proxy URL.
func singboxOutboundToUrl(proto string, settings, stream map[string]any, remark string) string {
	net := "tcp"
	if v, ok := stream["network"].(string); ok {
		net = v
	}
	security := "none"
	if v, ok := stream["security"].(string); ok {
		security = v
	}

	var fp, sni, pbk, sid, flow string
	if rs, ok := stream["realitySettings"].(map[string]any); ok {
		fp, _ = rs["fingerprint"].(string)
		sni, _ = rs["serverName"].(string)
		pbk, _ = rs["publicKey"].(string)
		sid, _ = rs["shortId"].(string)
		flow, _ = rs["flow"].(string)
	} else if ts, ok := stream["tlsSettings"].(map[string]any); ok {
		fp, _ = ts["fingerprint"].(string)
		sni, _ = ts["serverName"].(string)
	}

	switch proto {
	case "vless":
		vnext, ok := settings["vnext"].([]any)
		if !ok || len(vnext) == 0 {
			return ""
		}
		server, ok := vnext[0].(map[string]any)
		if !ok {
			return ""
		}
		users, _ := server["users"].([]any)
		var uuid string
		if len(users) > 0 {
			u, ok := users[0].(map[string]any)
			if ok {
				uuid, _ = u["id"].(string)
				if uuid == "" {
					uuid, _ = u["uuid"].(string)
				}
			}
		}
		address, _ := server["address"].(string)
		port := 443
		if v, ok := server["port"].(float64); ok {
			port = int(v)
		}

		params := url.Values{}
		if net != "" {
			params.Set("type", net)
		}
		if security != "" {
			params.Set("security", security)
		}
		if fp != "" {
			params.Set("fp", fp)
		}
		if sni != "" {
			params.Set("sni", sni)
		}
		if pbk != "" {
			params.Set("pbk", pbk)
		}
		if sid != "" {
			params.Set("sid", sid)
		}
		if flow != "" {
			params.Set("flow", flow)
		}
		// encryption from user settings
		if len(users) > 0 {
			u, ok := users[0].(map[string]any)
			if ok {
				if enc, ok := u["encryption"].(string); ok && enc != "" && enc != "none" {
					params.Set("encryption", enc)
				}
			}
		}

		// stream settings
		if xs, ok := stream["xhttpSettings"].(map[string]any); ok {
			if p, ok := xs["path"].(string); ok {
				params.Set("path", p)
			}
			if m, ok := xs["mode"].(string); ok {
				params.Set("mode", m)
			}
			if h, ok := xs["host"].(string); ok {
				params.Set("host", h)
			}
		}
		if ws, ok := stream["wsSettings"].(map[string]any); ok {
			if p, ok := ws["path"].(string); ok {
				params.Set("path", p)
			}
			if h, ok := ws["headers"].(map[string]any); ok {
				if host, ok := h["Host"].(string); ok {
					params.Set("host", host)
				}
			}
		}
		if gs, ok := stream["grpcSettings"].(map[string]any); ok {
			if sn, ok := gs["serviceName"].(string); ok {
				params.Set("serviceName", sn)
			}
			if m, ok := gs["mode"].(string); ok {
				params.Set("mode", m)
			}
		}
		if tc, ok := stream["tcpSettings"].(map[string]any); ok {
			if h, ok := tc["header"].(map[string]any); ok {
				if t, ok := h["type"].(string); ok && t == "http" {
					params.Set("headerType", "http")
				}
			}
		}

		frag := ""
		if remark != "" {
			frag = "#" + url.PathEscape(remark)
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s%s", uuid, address, port, params.Encode(), frag)

	case "vmess":
		vnext, ok := settings["vnext"].([]any)
		if !ok || len(vnext) == 0 {
			return ""
		}
		server, ok := vnext[0].(map[string]any)
		if !ok {
			return ""
		}
		users, _ := server["users"].([]any)
		var uuid string
		if len(users) > 0 {
			u, ok := users[0].(map[string]any)
			if ok {
				uuid, _ = u["id"].(string)
			}
		}
		address, _ := server["address"].(string)
		port := 443
		if v, ok := server["port"].(float64); ok {
			port = int(v)
		}

		vmConfig := map[string]any{
			"v":   "2",
			"ps":  remark,
			"add": address,
			"port": port,
			"id":  uuid,
			"aid": 0,
			"net": net,
			"type": net,
			"tls": "",
			"sni": sni,
			"path": "/",
			"host": "",
		}
		if security == "tls" || security == "reality" {
			vmConfig["tls"] = "tls"
		}
		if ws, ok := stream["wsSettings"].(map[string]any); ok {
			if p, ok := ws["path"].(string); ok {
				vmConfig["path"] = p
			}
			if h, ok := ws["headers"].(map[string]any); ok {
				if host, ok := h["Host"].(string); ok {
					vmConfig["host"] = host
				}
			}
		}
		if xs, ok := stream["xhttpSettings"].(map[string]any); ok {
			if p, ok := xs["path"].(string); ok {
				vmConfig["path"] = p
			}
			if h, ok := xs["host"].(string); ok {
				vmConfig["host"] = h
			}
		}

		jsonBytes, _ := json.Marshal(vmConfig)
		encoded := base64.StdEncoding.EncodeToString(jsonBytes)
		encoded = strings.TrimRight(encoded, "=")
		return "vmess://" + encoded

	case "trojan":
		servers, ok := settings["servers"].([]any)
		if !ok || len(servers) == 0 {
			return ""
		}
		server, ok := servers[0].(map[string]any)
		if !ok {
			return ""
		}
		password, _ := server["password"].(string)
		address, _ := server["address"].(string)
		port := 443
		if v, ok := server["port"].(float64); ok {
			port = int(v)
		}

		params := url.Values{}
		if security != "" {
			params.Set("security", security)
		}
		if sni != "" {
			params.Set("sni", sni)
		}
		if fp != "" {
			params.Set("fp", fp)
		}
		if net != "tcp" {
			params.Set("type", net)
		}

		frag := ""
		if remark != "" {
			frag = "#" + url.PathEscape(remark)
		}
		return fmt.Sprintf("trojan://%s@%s:%d?%s%s", password, address, port, params.Encode(), frag)

	case "shadowsocks":
		servers, ok := settings["servers"].([]any)
		if !ok || len(servers) == 0 {
			return ""
		}
		server, ok := servers[0].(map[string]any)
		if !ok {
			return ""
		}
		method := "aes-256-gcm"
		if m, ok := server["method"].(string); ok {
			method = m
		}
		password, _ := server["password"].(string)
		address, _ := server["address"].(string)
		port := 443
		if v, ok := server["port"].(float64); ok {
			port = int(v)
		}

		userInfo := base64.URLEncoding.EncodeToString([]byte(method + ":" + password))
		frag := ""
		if remark != "" {
			frag = "#" + url.PathEscape(remark)
		}
		return fmt.Sprintf("ss://%s@%s:%d%s", userInfo, address, port, frag)
	}

	return ""
}

func extractSingboxURLs(data json.RawMessage) []string {
	var items []map[string]any
	if err := json.Unmarshal(data, &items); err != nil {
		// Try single object
		var single map[string]any
		if err := json.Unmarshal(data, &single); err != nil {
			return nil
		}
		items = []map[string]any{single}
	}

	var urls []string
	for _, item := range items {
		outbounds, _ := item["outbounds"].([]any)
		remarks, _ := item["remarks"].(string)
		for _, ob := range outbounds {
			outbound, ok := ob.(map[string]any)
			if !ok {
				continue
			}
			proto, _ := outbound["protocol"].(string)
			if proto != "vless" && proto != "vmess" && proto != "trojan" && proto != "shadowsocks" {
				continue
			}
			tag, _ := outbound["tag"].(string)
			settings, _ := outbound["settings"].(map[string]any)
			stream, _ := outbound["streamSettings"].(map[string]any)
			if stream == nil {
				stream, _ = outbound["transport"].(map[string]any)
			}
			remark := remarks
			if remark == "" {
				remark = tag
			}
			if u := singboxOutboundToUrl(proto, settings, stream, remark); u != "" {
				urls = append(urls, u)
			} else {
				log.Printf("[fetch] singbox: skipped %s/%s (empty URL)", proto, tag)
			}
		}
	}
	return urls
}
