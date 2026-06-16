package format

import (
	"encoding/json"
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

// parseArray unmarshals the JSON array output and returns the first config.
// For single-entry tests, there should be exactly 1 config in the array.
func parseSingleConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var configs []map[string]any
	if err := json.Unmarshal(data, &configs); err != nil {
		t.Fatalf("invalid JSON array: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(configs))
	}
	return configs[0]
}

func TestFormatXrayJSON_VLESS_Reality(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.2.3.4",
				Port:           443,
				UUIDOrPassword: "test-uuid-1234",
				QueryParams: map[string]string{
					"type":       "tcp",
					"security":   "reality",
					"sni":        "example.com",
					"fp":         "chrome",
					"pbk":        "test-pbk-value",
					"sid":        "test-sid",
					"flow":       "xtls-rprx-vision",
					"encryption": "none",
				},
			},
			RenamedFragment: "DE Frankfurt (ISP)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{TotalAlive: 1})
	config := parseSingleConfig(t, result)

	// Check remarks
	if config["remarks"] != "DE Frankfurt (ISP)" {
		t.Errorf("expected remarks 'DE Frankfurt (ISP)', got %v", config["remarks"])
	}

	// Check inbounds exist
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds (socks+http), got %d", len(inbounds))
	}

	// Check outbounds count: proxy-1 + warp-out-1 + direct + block = 4
	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 4 {
		t.Fatalf("expected 4 outbounds, got %d", len(outbounds))
	}

	// Check proxy-1 (first outbound, detected by v2rayNG)
	proxy := outbounds[0].(map[string]any)
	if proxy["protocol"] != "vless" {
		t.Errorf("expected vless as first outbound, got %v", proxy["protocol"])
	}
	if proxy["tag"] != "proxy-1" {
		t.Errorf("expected tag proxy-1, got %v", proxy["tag"])
	}

	// Check warp-out-1 (second outbound, traffic routed here via catch-all rule)
	warp := outbounds[1].(map[string]any)
	if warp["protocol"] != "wireguard" {
		t.Errorf("expected wireguard outbound, got %v", warp["protocol"])
	}
	if warp["tag"] != "warp-out-1" {
		t.Errorf("expected tag warp-out-1, got %v", warp["tag"])
	}
	warpSS := warp["streamSettings"].(map[string]any)
	sockopt := warpSS["sockopt"].(map[string]any)
	if sockopt["dialerProxy"] != "proxy-1" {
		t.Errorf("expected dialerProxy proxy-1, got %v", sockopt["dialerProxy"])
	}

	// Check vnext
	vnext := proxy["settings"].(map[string]any)["vnext"].([]any)
	server := vnext[0].(map[string]any)
	if server["address"] != "1.2.3.4" {
		t.Errorf("expected address 1.2.3.4, got %v", server["address"])
	}
	user := server["users"].([]any)[0].(map[string]any)
	if user["encryption"] != "none" {
		t.Errorf("expected encryption none, got %v", user["encryption"])
	}
	if user["flow"] != "xtls-rprx-vision" {
		t.Errorf("expected flow xtls-rprx-vision, got %v", user["flow"])
	}

	// Check streamSettings
	ss := proxy["streamSettings"].(map[string]any)
	if ss["network"] != "raw" {
		t.Errorf("expected network raw, got %v", ss["network"])
	}
	if ss["security"] != "reality" {
		t.Errorf("expected security reality, got %v", ss["security"])
	}
	rs := ss["realitySettings"].(map[string]any)
	if rs["publicKey"] != "test-pbk-value" {
		t.Errorf("expected publicKey test-pbk-value, got %v", rs["publicKey"])
	}
	if rs["shortId"] != "test-sid" {
		t.Errorf("expected shortId test-sid, got %v", rs["shortId"])
	}

	// Check routing
	routing := config["routing"].(map[string]any)
	if routing["domainStrategy"] != "IPIfNonMatch" {
		t.Errorf("expected domainStrategy IPIfNonMatch, got %v", routing["domainStrategy"])
	}
	rules := routing["rules"].([]any)
	if len(rules) != 4 {
		t.Fatalf("expected 4 routing rules (block+direct+direct+catch-all warp), got %d", len(rules))
	}
	// Check catch-all WARP rule (last rule)
	catchAll := rules[3].(map[string]any)
	if catchAll["outboundTag"] != "warp-out-1" {
		t.Errorf("expected catch-all rule to route to warp-out-1, got %v", catchAll["outboundTag"])
	}
	if catchAll["port"] != "0-65535" {
		t.Errorf("expected catch-all port 0-65535, got %v", catchAll["port"])
	}
}

func TestFormatXrayJSON_VMess_WS_TLS(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VMess,
				Host:           "5.6.7.8",
				Port:           443,
				UUIDOrPassword: "vmess-uuid",
				QueryParams: map[string]string{
					"type":     "ws",
					"security": "tls",
					"sni":      "vmess.example.com",
					"path":     "/ws",
					"host":     "vmess.example.com",
					"scy":      "chacha20-poly1305",
					"alpn":     "h2,http/1.1",
				},
			},
			RenamedFragment: "US New York (Cloudflare)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	if proxy["protocol"] != "vmess" {
		t.Errorf("expected protocol vmess, got %v", proxy["protocol"])
	}

	user := proxy["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["security"] != "chacha20-poly1305" {
		t.Errorf("expected security chacha20-poly1305, got %v", user["security"])
	}

	ss := proxy["streamSettings"].(map[string]any)
	if ss["network"] != "websocket" {
		t.Errorf("expected network websocket, got %v", ss["network"])
	}
	if ss["security"] != "tls" {
		t.Errorf("expected security tls, got %v", ss["security"])
	}

	wsSettings := ss["wsSettings"].(map[string]any)
	if wsSettings["path"] != "/ws" {
		t.Errorf("expected path /ws, got %v", wsSettings["path"])
	}

	tlsSettings := ss["tlsSettings"].(map[string]any)
	alpn := tlsSettings["alpn"].([]any)
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("expected alpn [h2 http/1.1], got %v", alpn)
	}
}

func TestFormatXrayJSON_Trojan(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.Trojan,
				Host:           "9.8.7.6",
				Port:           443,
				UUIDOrPassword: "trojan-password",
				QueryParams: map[string]string{
					"type":     "tcp",
					"security": "tls",
					"sni":      "trojan.example.com",
				},
			},
			RenamedFragment: "NL Amsterdam (Leaseweb)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	if proxy["protocol"] != "trojan" {
		t.Errorf("expected protocol trojan, got %v", proxy["protocol"])
	}
	server := proxy["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server["password"] != "trojan-password" {
		t.Errorf("expected password trojan-password, got %v", server["password"])
	}
}

func TestFormatXrayJSON_SS(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.SS,
				Host:           "10.0.0.1",
				Port:           8388,
				UUIDOrPassword: "ss-password",
				QueryParams: map[string]string{
					"method": "aes-256-gcm",
				},
			},
			RenamedFragment: "JP Tokyo (Vultr)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	if proxy["protocol"] != "shadowsocks" {
		t.Errorf("expected protocol shadowsocks, got %v", proxy["protocol"])
	}
	server := proxy["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server["method"] != "aes-256-gcm" {
		t.Errorf("expected method aes-256-gcm, got %v", server["method"])
	}
}

func TestFormatXrayJSON_Hysteria2(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.Hysteria2,
				Host:           "11.0.0.1",
				Port:           443,
				UUIDOrPassword: "hy2-auth",
				QueryParams: map[string]string{
					"type":          "quic",
					"security":      "tls",
					"sni":           "hy2.example.com",
					"obfs":          "salamander",
					"obfs-password": "obfs-pass",
				},
			},
			RenamedFragment: "FI Helsinki (Hetzner)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	if proxy["protocol"] != "hysteria" {
		t.Fatalf("expected protocol hysteria (hysteria2), got %v", proxy["protocol"])
	}

	// Settings must use flat format (not servers array)
	settings := proxy["settings"].(map[string]any)
	if settings["address"] != "11.0.0.1" {
		t.Errorf("expected address 11.0.0.1, got %v", settings["address"])
	}
	if settings["port"] != float64(443) {
		t.Errorf("expected port 443, got %v", settings["port"])
	}
	if settings["password"] != "hy2-auth" {
		t.Errorf("expected password hy2-auth, got %v", settings["password"])
	}
	if settings["version"] != float64(2) {
		t.Errorf("expected version 2, got %v", settings["version"])
	}
	// Must NOT have "servers" key
	if _, ok := settings["servers"]; ok {
		t.Error("hysteria settings must NOT use servers array format")
	}

	// streamSettings must exist with hysteriaSettings
	ss := proxy["streamSettings"].(map[string]any)
	if ss["network"] != "hysteria" {
		t.Errorf("expected network hysteria, got %v", ss["network"])
	}
	if ss["security"] != "tls" {
		t.Errorf("expected security tls, got %v", ss["security"])
	}
	hy := ss["hysteriaSettings"].(map[string]any)
	if hy["version"] != float64(2) {
		t.Errorf("expected hysteriaSettings version 2, got %v", hy["version"])
	}
	if hy["auth"] != "hy2-auth" {
		t.Errorf("expected hysteriaSettings auth hy2-auth, got %v", hy["auth"])
	}
	if hy["obfs"] != "salamander" {
		t.Errorf("expected obfs salamander, got %v", hy["obfs"])
	}
	if hy["obfsPassword"] != "obfs-pass" {
		t.Errorf("expected obfsPassword obfs-pass, got %v", hy["obfsPassword"])
	}
	// TLS settings must have SNI
	tlsSettings := ss["tlsSettings"].(map[string]any)
	if tlsSettings["serverName"] != "hy2.example.com" {
		t.Errorf("expected serverName hy2.example.com, got %v", tlsSettings["serverName"])
	}
}

func TestFormatXrayJSON_MultipleProxies(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.1.1.1",
				Port:           443,
				UUIDOrPassword: "uuid-1",
				QueryParams:    map[string]string{"type": "tcp", "security": "reality", "sni": "a.com", "fp": "chrome", "pbk": "pbk1", "sid": "sid1"},
			},
			RenamedFragment: "Proxy 1",
		},
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "2.2.2.2",
				Port:           443,
				UUIDOrPassword: "uuid-2",
				QueryParams:    map[string]string{"type": "ws", "security": "tls", "sni": "b.com", "path": "/ws"},
			},
			RenamedFragment: "Proxy 2",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	var configs []map[string]any
	if err := json.Unmarshal(result, &configs); err != nil {
		t.Fatalf("invalid JSON array: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}

	// First config
	c1 := configs[0]
	if c1["remarks"] != "Proxy 1" {
		t.Errorf("first config remarks should be 'Proxy 1', got %v", c1["remarks"])
	}
	ob1 := c1["outbounds"].([]any)
	if ob1[0].(map[string]any)["tag"] != "proxy-1" {
		t.Errorf("first config first outbound tag should be proxy-1")
	}
	if ob1[1].(map[string]any)["tag"] != "warp-out-1" {
		t.Errorf("first config second outbound tag should be warp-out-1")
	}

	// Second config
	c2 := configs[1]
	if c2["remarks"] != "Proxy 2" {
		t.Errorf("second config remarks should be 'Proxy 2', got %v", c2["remarks"])
	}
	ob2 := c2["outbounds"].([]any)
	if ob2[0].(map[string]any)["tag"] != "proxy-2" {
		t.Errorf("second config first outbound tag should be proxy-2")
	}
	if ob2[1].(map[string]any)["tag"] != "warp-out-2" {
		t.Errorf("second config second outbound tag should be warp-out-2")
	}

	// WARP dialerProxy for proxy-2
	warp2SS := ob2[1].(map[string]any)["streamSettings"].(map[string]any)
	sockopt2 := warp2SS["sockopt"].(map[string]any)
	if sockopt2["dialerProxy"] != "proxy-2" {
		t.Errorf("expected dialerProxy proxy-2, got %v", sockopt2["dialerProxy"])
	}
}

func TestFormatXrayJSON_Empty(t *testing.T) {
	result := FormatXrayJSON(nil, FormatMetadata{})
	var configs []map[string]any
	if err := json.Unmarshal(result, &configs); err != nil {
		t.Fatalf("invalid JSON array: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("expected 0 configs for empty input, got %d", len(configs))
	}
}

func TestFormatXrayJSON_PQEncryption(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.2.3.4",
				Port:           443,
				UUIDOrPassword: "uuid-pq",
				QueryParams: map[string]string{
					"type":       "tcp",
					"security":   "reality",
					"sni":        "pq.example.com",
					"fp":         "chrome",
					"pbk":        "pq-pbk",
					"sid":        "pq-sid",
					"encryption": "mlkem768x25519plus",
				},
			},
			RenamedFragment: "PQ Test",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	user := proxy["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["encryption"] != "mlkem768x25519plus" {
		t.Errorf("PQ encryption must be preserved, got %v", user["encryption"])
	}
}

func TestFormatXrayJSON_GRPC(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "grpc.example.com",
				Port:           443,
				UUIDOrPassword: "grpc-uuid",
				QueryParams: map[string]string{
					"type":        "grpc",
					"security":    "tls",
					"sni":         "grpc.example.com",
					"serviceName": "grpc-service",
					"mode":        "multi",
				},
			},
			RenamedFragment: "gRPC Proxy",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	proxy := config["outbounds"].([]any)[0].(map[string]any)
	ss := proxy["streamSettings"].(map[string]any)
	if ss["network"] != "grpc" {
		t.Errorf("expected network grpc, got %v", ss["network"])
	}
	grpcSettings := ss["grpcSettings"].(map[string]any)
	if grpcSettings["serviceName"] != "grpc-service" {
		t.Errorf("expected serviceName grpc-service, got %v", grpcSettings["serviceName"])
	}
	if grpcSettings["multiMode"] != true {
		t.Errorf("expected multiMode true, got %v", grpcSettings["multiMode"])
	}
}

func TestFormatXrayJSON_RoutingBlockRules(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.1.1.1",
				Port:           443,
				UUIDOrPassword: "uuid",
				QueryParams:    map[string]string{"type": "tcp", "security": "reality", "sni": "a.com", "fp": "chrome", "pbk": "p", "sid": "s"},
			},
			RenamedFragment: "Test",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	rules := config["routing"].(map[string]any)["rules"].([]any)

	// Rule 0: block
	blockRule := rules[0].(map[string]any)
	if blockRule["outboundTag"] != "block" {
		t.Errorf("first rule should be block, got %v", blockRule["outboundTag"])
	}
	domains := blockRule["domain"].([]any)
	hasAds := false
	for _, d := range domains {
		if d == "geosite:category-ads" {
			hasAds = true
		}
	}
	if !hasAds {
		t.Error("block rule should contain geosite:category-ads")
	}

	// Rule 2: direct with domain_suffix
	directRule2 := rules[2].(map[string]any)
	if directRule2["outboundTag"] != "direct" {
		t.Errorf("third rule should be direct, got %v", directRule2["outboundTag"])
	}
	suffixes := directRule2["domain_suffix"].([]any)
	if len(suffixes) != 1 || suffixes[0] != ".kg" {
		t.Errorf("expected domain_suffix [.kg], got %v", suffixes)
	}
}

func TestFormatXrayJSON_InboundsPresent(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.2.3.4",
				Port:           443,
				UUIDOrPassword: "test-uuid",
				QueryParams:    map[string]string{"type": "tcp", "security": "reality", "sni": "a.com", "fp": "chrome", "pbk": "p", "sid": "s"},
			},
			RenamedFragment: "Test Inbounds",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	// Verify first outbound is the proxy (v2rayNG detection)
	outbounds := config["outbounds"].([]any)
	if outbounds[0].(map[string]any)["protocol"] != "vless" {
		t.Errorf("expected first outbound to be proxy protocol (vless)")
	}

	// Verify inbounds exist with socks and http
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(inbounds))
	}
	socks := inbounds[0].(map[string]any)
	if socks["protocol"] != "socks" {
		t.Errorf("expected socks inbound, got %v", socks["protocol"])
	}
	http := inbounds[1].(map[string]any)
	if http["protocol"] != "http" {
		t.Errorf("expected http inbound, got %v", http["protocol"])
	}

	// Fixed ports (same for all profiles)
	socksPort := socks["port"].(float64)
	httpPort := http["port"].(float64)
	if socksPort != 10808 {
		t.Errorf("expected socks port 10808, got %v", socksPort)
	}
	if httpPort != 10809 {
		t.Errorf("expected http port 10809, got %v", httpPort)
	}
}

func TestFormatXrayJSON_RemarksField(t *testing.T) {
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.2.3.4",
				Port:           443,
				UUIDOrPassword: "uuid",
				QueryParams:    map[string]string{"type": "tcp", "security": "reality", "sni": "a.com", "fp": "chrome", "pbk": "p", "sid": "s"},
			},
			RenamedFragment: "🇩🇪 Frankfurt (Hetzner)",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	config := parseSingleConfig(t, result)

	if config["remarks"] != "🇩🇪 Frankfurt (Hetzner)" {
		t.Errorf("expected remarks '🇩🇪 Frankfurt (Hetzner)', got %v", config["remarks"])
	}
}

func TestFormatXrayJSON_ArrayFormatForV2rayNG(t *testing.T) {
	// Verify the output is a JSON array that contains "inbounds" string
	// so v2rayNG's string-contains detection works
	entries := []rename.RenamedEntry{
		{
			Record: parse.ProxyRecord{
				Protocol:       parse.VLESS,
				Host:           "1.2.3.4",
				Port:           443,
				UUIDOrPassword: "uuid",
				QueryParams:    map[string]string{"type": "tcp", "security": "reality", "sni": "a.com", "fp": "chrome", "pbk": "p", "sid": "s"},
			},
			RenamedFragment: "Server A",
		},
	}

	result := FormatXrayJSON(entries, FormatMetadata{})
	resultStr := string(result)

	// v2rayNG checks: server.contains("inbounds") && server.contains("outbounds") && server.contains("routing")
	if !containsAll(resultStr, "inbounds", "outbounds", "routing") {
		t.Error("output must contain 'inbounds', 'outbounds', 'routing' for v2rayNG detection")
	}

	// Must be a JSON array (starts with '[')
	var arr []any
	if err := json.Unmarshal(result, &arr); err != nil {
		t.Fatalf("output must be valid JSON array: %v", err)
	}
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !jsonOrPlainContains(s, sub) {
			return false
		}
	}
	return true
}

func jsonOrPlainContains(s, sub string) bool {
	return len(s) >= len(sub) && containsStr(s, sub)
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}