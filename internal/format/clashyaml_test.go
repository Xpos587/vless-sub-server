package format

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
	"gopkg.in/yaml.v3"
)

func clashEntry(name string, record parse.ProxyRecord) rename.RenamedEntry {
	return rename.RenamedEntry{Record: record, RenamedFragment: name}
}

func parseClashConfig(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("invalid clash yaml: %v\n%s", err, data)
	}
	return config
}

func clashProxies(t *testing.T, config map[string]any) map[string]map[string]any {
	t.Helper()
	raw, ok := config["proxies"].([]any)
	if !ok {
		t.Fatalf("proxies missing: %#v", config)
	}
	result := map[string]map[string]any{}
	for _, item := range raw {
		proxy := item.(map[string]any)
		result[proxy["name"].(string)] = proxy
	}
	return result
}

func clashGroups(t *testing.T, config map[string]any) map[string]map[string]any {
	t.Helper()
	raw, ok := config["proxy-groups"].([]any)
	if !ok {
		t.Fatalf("proxy-groups missing: %#v", config)
	}
	result := map[string]map[string]any{}
	for _, item := range raw {
		group := item.(map[string]any)
		result[group["name"].(string)] = group
	}
	return result
}

func TestFormatClashYAMLVLESSRealityVision(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("NL Vision", parse.ProxyRecord{
		Protocol:       parse.VLESS,
		Host:           "nl.example.com",
		Port:           443,
		UUIDOrPassword: "uuid-1",
		QueryParams: map[string]string{
			"type": "tcp", "security": "reality", "flow": "xtls-rprx-vision",
			"sni": "www.booking.com", "pbk": "pubkey", "sid": "b4", "fp": "firefox",
		},
	})}

	config := parseClashConfig(t, FormatClashYAML(entries, FormatMetadata{}))
	proxy := clashProxies(t, config)["NL Vision"]
	if proxy == nil {
		t.Fatalf("vless proxy missing: %#v", config["proxies"])
	}
	if proxy["type"] != "vless" || proxy["server"] != "nl.example.com" || proxy["port"] != 443 || proxy["uuid"] != "uuid-1" {
		t.Fatalf("vless fields wrong: %#v", proxy)
	}
	if proxy["flow"] != "xtls-rprx-vision" || proxy["udp"] != true {
		t.Fatalf("flow/udp wrong: %#v", proxy)
	}
	if proxy["tls"] != true || proxy["servername"] != "www.booking.com" || proxy["client-fingerprint"] != "firefox" {
		t.Fatalf("tls fields wrong: %#v", proxy)
	}
	reality := proxy["reality-opts"].(map[string]any)
	if reality["public-key"] != "pubkey" || reality["short-id"] != "b4" {
		t.Fatalf("reality-opts wrong: %#v", reality)
	}
	if _, hasNetwork := proxy["network"]; hasNetwork {
		t.Fatalf("tcp network must be omitted: %#v", proxy)
	}
}

func TestFormatClashYAMLTrojanWS(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("Trojan WS", parse.ProxyRecord{
		Protocol:       parse.Trojan,
		Host:           "tr.example.com",
		Port:           8443,
		UUIDOrPassword: "secret",
		QueryParams: map[string]string{
			"type": "ws", "security": "tls", "sni": "cdn.example.com",
			"host": "cdn.example.com", "path": "/ws",
		},
	})}

	config := parseClashConfig(t, FormatClashYAML(entries, FormatMetadata{}))
	proxy := clashProxies(t, config)["Trojan WS"]
	if proxy["type"] != "trojan" || proxy["password"] != "secret" || proxy["sni"] != "cdn.example.com" {
		t.Fatalf("trojan wrong: %#v", proxy)
	}
	if proxy["network"] != "ws" {
		t.Fatalf("ws network missing: %#v", proxy)
	}
	wsOpts := proxy["ws-opts"].(map[string]any)
	if wsOpts["path"] != "/ws" {
		t.Fatalf("ws-opts wrong: %#v", wsOpts)
	}
	headers := wsOpts["headers"].(map[string]any)
	if headers["Host"] != "cdn.example.com" {
		t.Fatalf("ws host lost: %#v", wsOpts)
	}
}

func TestFormatClashYAMLHysteria2Obfs(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("Hy2", parse.ProxyRecord{
		Protocol:       parse.Hysteria2,
		Host:           "hy.example.com",
		Port:           443,
		UUIDOrPassword: "password",
		QueryParams: map[string]string{
			"sni": "hy.example.com", "obfs": "salamander", "obfs-password": "obfs-pass",
			"insecure": "1",
		},
	})}

	config := parseClashConfig(t, FormatClashYAML(entries, FormatMetadata{}))
	proxy := clashProxies(t, config)["Hy2"]
	if proxy["type"] != "hysteria2" || proxy["password"] != "password" {
		t.Fatalf("hysteria2 wrong: %#v", proxy)
	}
	if proxy["sni"] != "hy.example.com" || proxy["skip-cert-verify"] != true {
		t.Fatalf("hy2 tls wrong: %#v", proxy)
	}
	if proxy["obfs"] != "salamander" || proxy["obfs-password"] != "obfs-pass" {
		t.Fatalf("obfs wrong: %#v", proxy)
	}
}

func TestFormatClashYAMLFiltersUnsupportedTransports(t *testing.T) {
	entries := []rename.RenamedEntry{
		clashEntry("xhttp-node", parse.ProxyRecord{
			Protocol: parse.VLESS, Host: "x.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "xhttp", "security": "reality", "pbk": "k"},
		}),
		clashEntry("kcp-node", parse.ProxyRecord{
			Protocol: parse.VMess, Host: "k.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "kcp"},
		}),
		clashEntry("grpc-node", parse.ProxyRecord{
			Protocol: parse.VLESS, Host: "g.example.com", Port: 443, UUIDOrPassword: "u",
			QueryParams: map[string]string{"type": "grpc", "serviceName": "svc", "security": "tls", "sni": "g.example.com"},
		}),
	}

	config := parseClashConfig(t, FormatClashYAML(entries, FormatMetadata{}))
	proxies := clashProxies(t, config)
	if _, ok := proxies["xhttp-node"]; ok {
		t.Fatal("xhttp must be filtered for clash")
	}
	if _, ok := proxies["kcp-node"]; ok {
		t.Fatal("kcp must be filtered for clash")
	}
	grpc := proxies["grpc-node"]
	if grpc == nil || grpc["network"] != "grpc" {
		t.Fatalf("grpc node wrong: %#v", grpc)
	}
	if grpc["grpc-opts"].(map[string]any)["grpc-service-name"] != "svc" {
		t.Fatalf("grpc-opts wrong: %#v", grpc)
	}
	groups := clashGroups(t, config)
	selectGroup := groups["PROXY"]
	if selectGroup == nil || selectGroup["type"] != "select" {
		t.Fatalf("select group missing: %#v", groups)
	}
	listed := selectGroup["proxies"].([]any)
	if len(listed) != 2 || listed[0] != "AUTO" || listed[1] != "grpc-node" {
		t.Fatalf("select group wrong: %#v", listed)
	}
}

func TestFormatClashYAMLWarpChainViaRelay(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp", "security": "reality", "pbk": "k"},
	})}

	config := parseClashConfig(t, FormatClashYAMLWithOptions(entries, FormatMetadata{}, ClashOptions{Warp: true, Profile: RoutingProfileRussia}))
	proxies := clashProxies(t, config)
	warpProxy := proxies["warp"]
	if warpProxy == nil || warpProxy["type"] != "wireguard" {
		t.Fatalf("warp wireguard proxy missing: %#v", proxies)
	}
	if warpProxy["private-key"] == nil || warpProxy["public-key"] == nil {
		t.Fatalf("warp keys missing: %#v", warpProxy)
	}
	groups := clashGroups(t, config)
	relay := groups["WARP"]
	if relay == nil || relay["type"] != "relay" {
		t.Fatalf("relay group missing: %#v", groups)
	}
	members := relay["proxies"].([]any)
	if len(members) != 2 || members[0] != "PROXY" || members[1] != "warp" {
		t.Fatalf("relay chain must be PROXY -> warp: %#v", members)
	}
	rules := config["rules"].([]any)
	last := rules[len(rules)-1].(string)
	if last != "MATCH,WARP" {
		t.Fatalf("MATCH must point at WARP: %s", last)
	}
}

func TestFormatClashYAMLWarpOff(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp", "security": "reality", "pbk": "k"},
	})}

	config := parseClashConfig(t, FormatClashYAMLWithOptions(entries, FormatMetadata{}, ClashOptions{Warp: false, Profile: RoutingProfileRussia}))
	proxies := clashProxies(t, config)
	if _, ok := proxies["warp"]; ok {
		t.Fatal("warp proxy must be omitted when warp=off")
	}
	rules := config["rules"].([]any)
	last := rules[len(rules)-1].(string)
	if last != "MATCH,PROXY" {
		t.Fatalf("MATCH must point at PROXY: %s", last)
	}
}

func TestFormatClashYAMLRussiaProfileRulesAndDNS(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp"},
	})}

	config := parseClashConfig(t, FormatClashYAML(entries, FormatMetadata{}))
	rules := config["rules"].([]any)
	joined := ""
	for _, r := range rules {
		joined += r.(string) + "\n"
	}
	for _, want := range []string{
		"GEOSITE,category-ads-all,REJECT",
		"GEOSITE,category-ip-geo-detect,REJECT",
		"GEOSITE,ozon,DIRECT",
		"GEOSITE,wildberries,DIRECT",
		"GEOSITE,category-ru,DIRECT",
		"DOMAIN-SUFFIX,ru,DIRECT",
		"GEOIP,ru,DIRECT",
	} {
		if !containsAll(joined, want) {
			t.Fatalf("rule %q missing in:\n%s", want, joined)
		}
	}

	dns := config["dns"].(map[string]any)
	if dns["enable"] != true || dns["ipv6"] != false {
		t.Fatalf("dns wrong: %#v", dns)
	}
	proxyNS := dns["proxy-server-nameserver"].([]any)
	if len(proxyNS) == 0 || proxyNS[0] != "https://77.88.8.8/dns-query" {
		t.Fatalf("proxy-server-nameserver wrong: %#v", proxyNS)
	}
	nameserver := dns["nameserver"].([]any)
	if len(nameserver) == 0 || nameserver[0] != "https://1.1.1.1/dns-query#WARP" {
		t.Fatalf("nameserver must go through warp chain: %#v", nameserver)
	}
	policy := dns["nameserver-policy"].(map[string]any)
	foundYandex := false
	for key, value := range policy {
		servers := value.([]any)
		if servers[0] == "https://77.88.8.8/dns-query" && (containsAll(key, "category-ru") || containsAll(key, ".ru")) {
			foundYandex = true
		}
	}
	if !foundYandex {
		t.Fatalf("nameserver-policy must route ru domains to yandex: %#v", policy)
	}
}

func TestFormatClashYAMLNeutralProfile(t *testing.T) {
	entries := []rename.RenamedEntry{clashEntry("node", parse.ProxyRecord{
		Protocol: parse.VLESS, Host: "a.example.com", Port: 443, UUIDOrPassword: "u",
		QueryParams: map[string]string{"type": "tcp"},
	})}

	config := parseClashConfig(t, FormatClashYAMLWithOptions(entries, FormatMetadata{}, ClashOptions{Warp: true, Profile: RoutingProfileNone}))
	rules := config["rules"].([]any)
	for _, r := range rules {
		rule := r.(string)
		if containsAll(rule, "GEOSITE") || (containsAll(rule, "GEOIP") && !containsAll(rule, "private")) {
			t.Fatalf("neutral profile must not reference ru geo rules: %s", rule)
		}
	}
	dns := config["dns"].(map[string]any)
	if _, ok := dns["nameserver-policy"]; ok {
		t.Fatalf("neutral profile must not have nameserver-policy: %#v", dns)
	}
}
