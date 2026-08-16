package format

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

func singboxEntry(name string, record parse.ProxyRecord) rename.RenamedEntry {
	return rename.RenamedEntry{Record: record, RenamedFragment: name}
}

func parseSingboxConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid sing-box config: %v\n%s", err, data)
	}
	return config
}

func outboundsByTag(t *testing.T, config map[string]any) map[string]map[string]any {
	t.Helper()
	outbounds, ok := config["outbounds"].([]any)
	if !ok {
		t.Fatalf("outbounds missing: %#v", config)
	}
	result := map[string]map[string]any{}
	for _, raw := range outbounds {
		ob := raw.(map[string]any)
		tag, _ := ob["tag"].(string)
		result[tag] = ob
	}
	return result
}

func TestFormatSingboxJSONVLESSRealityVision(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("🇳🇱 NL (VLESS)", parse.ProxyRecord{
		Protocol:       parse.VLESS,
		Host:           "nl.example.com",
		Port:           443,
		UUIDOrPassword: "uuid-1",
		QueryParams: map[string]string{
			"type": "tcp", "security": "reality", "flow": "xtls-rprx-vision",
			"sni": "www.booking.com", "pbk": "pubkey", "sid": "b4", "fp": "firefox",
		},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSON(entries, FormatMetadata{}))
	ob := outboundsByTag(t, config)["🇳🇱 NL (VLESS)"]
	if ob == nil {
		t.Fatalf("VLESS outbound missing: %#v", config["outbounds"])
	}
	if ob["type"] != "vless" || ob["server"] != "nl.example.com" || ob["server_port"] != float64(443) || ob["uuid"] != "uuid-1" {
		t.Fatalf("VLESS fields wrong: %#v", ob)
	}
	if ob["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow lost: %#v", ob)
	}
	tls := ob["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "www.booking.com" {
		t.Fatalf("tls wrong: %#v", tls)
	}
	utls := tls["utls"].(map[string]any)
	if utls["enabled"] != true || utls["fingerprint"] != "firefox" {
		t.Fatalf("utls wrong: %#v", utls)
	}
	reality := tls["reality"].(map[string]any)
	if reality["enabled"] != true || reality["public_key"] != "pubkey" || reality["short_id"] != "b4" {
		t.Fatalf("reality wrong: %#v", reality)
	}
	if _, hasTransport := ob["transport"]; hasTransport {
		t.Fatalf("tcp transport must be omitted: %#v", ob)
	}
}

func TestFormatSingboxJSONTrojanWS(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("Trojan WS", parse.ProxyRecord{
		Protocol:       parse.Trojan,
		Host:           "tr.example.com",
		Port:           8443,
		UUIDOrPassword: "secret",
		QueryParams: map[string]string{
			"type": "ws", "security": "tls", "sni": "cdn.example.com",
			"host": "cdn.example.com", "path": "/ws",
		},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSON(entries, FormatMetadata{}))
	ob := outboundsByTag(t, config)["Trojan WS"]
	if ob["type"] != "trojan" || ob["password"] != "secret" {
		t.Fatalf("trojan wrong: %#v", ob)
	}
	transport := ob["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/ws" {
		t.Fatalf("ws transport wrong: %#v", transport)
	}
	headers := transport["headers"].(map[string]any)
	if headers["Host"] != "cdn.example.com" {
		t.Fatalf("ws host header lost: %#v", transport)
	}
	tls := ob["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "cdn.example.com" {
		t.Fatalf("tls wrong: %#v", tls)
	}
}

func TestFormatSingboxJSONHysteria2Obfs(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("Hy2", parse.ProxyRecord{
		Protocol:       parse.Hysteria2,
		Host:           "hy.example.com",
		Port:           443,
		UUIDOrPassword: "password",
		QueryParams: map[string]string{
			"sni": "hy.example.com", "obfs": "salamander", "obfs-password": "obfs-pass",
			"insecure": "1",
		},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSON(entries, FormatMetadata{}))
	ob := outboundsByTag(t, config)["Hy2"]
	if ob["type"] != "hysteria2" || ob["password"] != "password" {
		t.Fatalf("hysteria2 wrong: %#v", ob)
	}
	tls := ob["tls"].(map[string]any)
	if tls["enabled"] != true || tls["server_name"] != "hy.example.com" || tls["insecure"] != true {
		t.Fatalf("hy2 tls wrong: %#v", tls)
	}
	obfs := ob["obfs"].(map[string]any)
	if obfs["type"] != "salamander" || obfs["password"] != "obfs-pass" {
		t.Fatalf("obfs wrong: %#v", obfs)
	}
}

func TestFormatSingboxJSONFiltersUnsupportedTransports(t *testing.T) {
	entries := []rename.RenamedEntry{
		singboxEntry("xhttp-node", parse.ProxyRecord{
			Protocol: parse.VLESS, Host: "x.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "xhttp", "security": "reality", "pbk": "k"},
		}),
		singboxEntry("kcp-node", parse.ProxyRecord{
			Protocol: parse.VMess, Host: "k.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "kcp"},
		}),
		singboxEntry("grpc-node", parse.ProxyRecord{
			Protocol: parse.VLESS, Host: "g.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "grpc", "serviceName": "svc", "security": "tls", "sni": "g.example.com"},
		}),
	}

	config := parseSingboxConfig(t, FormatSingboxJSON(entries, FormatMetadata{}))
	byTag := outboundsByTag(t, config)
	if _, ok := byTag["xhttp-node"]; ok {
		t.Fatal("xhttp node must be filtered for sing-box")
	}
	if _, ok := byTag["kcp-node"]; ok {
		t.Fatal("kcp node must be filtered for sing-box")
	}
	grpc := byTag["grpc-node"]
	if grpc == nil {
		t.Fatal("grpc node must be kept")
	}
	transport := grpc["transport"].(map[string]any)
	if transport["type"] != "grpc" || transport["service_name"] != "svc" {
		t.Fatalf("grpc transport wrong: %#v", transport)
	}
	selector := byTag["proxy"]
	if selector == nil || selector["type"] != "selector" {
		t.Fatalf("selector missing: %#v", byTag)
	}
	listed := selector["outbounds"].([]any)
	if len(listed) != 2 || listed[0] != "auto" || listed[1] != "grpc-node" {
		t.Fatalf("selector outbounds wrong: %#v", listed)
	}
}

func TestFormatSingboxJSONWarpChainUsesDetour(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp", "security": "reality", "pbk": "k"},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSONWithOptions(entries, FormatMetadata{}, SingboxOptions{Warp: true, Profile: RoutingProfileRussia}))
	endpoints, ok := config["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		t.Fatalf("warp endpoint missing: %#v", config["endpoints"])
	}
	warpEp := endpoints[0].(map[string]any)
	if warpEp["type"] != "wireguard" || warpEp["tag"] != "warp-out" {
		t.Fatalf("warp endpoint wrong: %#v", warpEp)
	}
	if warpEp["detour"] != "proxy" {
		t.Fatalf("warp must detour through selector, got %#v", warpEp)
	}
	route := config["route"].(map[string]any)
	if route["final"] != "warp-out" {
		t.Fatalf("route final must be warp-out, got %#v", route["final"])
	}
}

func TestFormatSingboxJSONWarpOff(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp", "security": "reality", "pbk": "k"},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSONWithOptions(entries, FormatMetadata{}, SingboxOptions{Warp: false, Profile: RoutingProfileRussia}))
	if _, ok := config["endpoints"]; ok {
		t.Fatal("warp endpoint must be omitted when warp=off")
	}
	route := config["route"].(map[string]any)
	if route["final"] != "proxy" {
		t.Fatalf("route final must be proxy, got %#v", route["final"])
	}
}

func TestFormatSingboxJSONRussiaProfileRules(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp"},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSON(entries, FormatMetadata{}))
	route := config["route"].(map[string]any)
	ruleSets := route["rule_set"].([]any)
	setTags := map[string]bool{}
	for _, raw := range ruleSets {
		rs := raw.(map[string]any)
		setTags[rs["tag"].(string)] = true
		if rs["type"] != "remote" || rs["format"] != "binary" {
			t.Fatalf("rule_set must be remote binary: %#v", rs)
		}
	}
	for _, want := range []string{
		"geosite-category-ads-all", "geosite-category-ip-geo-detect",
		"geosite-ozon", "geosite-wildberries", "geosite-category-ru", "geosite-category-gov-ru",
		"geoip-ru",
	} {
		if !setTags[want] {
			t.Fatalf("rule_set %s missing: %#v", want, setTags)
		}
	}

	rules := route["rules"].([]any)
	var reject, sawRuSuffix, sawGeoipRu bool
	for _, raw := range rules {
		rule := raw.(map[string]any)
		if rule["action"] == "reject" {
			reject = true
			sets := rule["rule_set"].([]any)
			joined := ""
			for _, s := range sets {
				joined += s.(string) + ","
			}
			if !strings.Contains(joined, "category-ip-geo-detect") || !strings.Contains(joined, "category-ads-all") {
				t.Fatalf("reject rule must block ads+ip checkers: %#v", rule)
			}
		}
		if suffixes, ok := rule["domain_suffix"].([]any); ok {
			for _, s := range suffixes {
				if s == ".ru" {
					sawRuSuffix = true
				}
			}
		}
		if sets, ok := rule["rule_set"].([]any); ok && rule["outbound"] == "direct" {
			for _, s := range sets {
				if s == "geoip-ru" {
					sawGeoipRu = true
				}
			}
		}
	}
	if !reject || !sawRuSuffix || !sawGeoipRu {
		t.Fatalf("ru rules incomplete: reject=%t ruSuffix=%t geoipRu=%t rules=%#v", reject, sawRuSuffix, sawGeoipRu, rules)
	}

	dns := config["dns"].(map[string]any)
	if dns["strategy"] != "ipv4_only" || dns["final"] != "cloudflare" {
		t.Fatalf("dns wrong: %#v", dns)
	}
	servers := dns["servers"].([]any)
	serverTags := map[string]map[string]any{}
	for _, raw := range servers {
		s := raw.(map[string]any)
		serverTags[s["tag"].(string)] = s
	}
	yandex := serverTags["yandex"]
	if yandex == nil || yandex["type"] != "https" || yandex["server"] != "77.88.8.8" || yandex["detour"] != "direct" {
		t.Fatalf("yandex dns server wrong: %#v", yandex)
	}
	cloudflare := serverTags["cloudflare"]
	if cloudflare == nil || cloudflare["server"] != "1.1.1.1" || cloudflare["detour"] != "warp-out" {
		t.Fatalf("cloudflare dns server wrong: %#v", cloudflare)
	}
	resolver := route["default_domain_resolver"].(map[string]any)
	if resolver["server"] != "yandex" {
		t.Fatalf("default domain resolver wrong: %#v", resolver)
	}
	dnsRules := dns["rules"].([]any)
	if len(dnsRules) == 0 {
		t.Fatal("dns rules missing for ru profile")
	}
	first := dnsRules[0].(map[string]any)
	if first["server"] != "yandex" {
		t.Fatalf("first dns rule must route ru domains to yandex: %#v", first)
	}
}

func TestFormatSingboxJSONNeutralProfile(t *testing.T) {
	entries := []rename.RenamedEntry{singboxEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp"},
	})}

	config := parseSingboxConfig(t, FormatSingboxJSONWithOptions(entries, FormatMetadata{}, SingboxOptions{Warp: true, Profile: RoutingProfileNone}))
	route := config["route"].(map[string]any)
	if _, ok := route["rule_set"]; ok {
		t.Fatalf("neutral profile must not reference rule_sets: %#v", route["rule_set"])
	}
	resolver := route["default_domain_resolver"].(map[string]any)
	if resolver["server"] != "bootstrap" {
		t.Fatalf("neutral resolver wrong: %#v", resolver)
	}
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("neutral profile must have bootstrap+cloudflare dns: %#v", servers)
	}
	if rules, ok := dns["rules"].([]any); ok && len(rules) != 0 {
		t.Fatalf("neutral profile must have no dns rules: %#v", rules)
	}
}
