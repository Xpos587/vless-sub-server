package format

import (
	"strings"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
	"github.com/michael/vless-sub-server/internal/warp"
	"gopkg.in/yaml.v3"
)

// ClashOptions selects the policy embedded in a mihomo (Clash.Meta) config.
type ClashOptions struct {
	Warp    bool
	Profile RoutingProfile
}

// FormatClashYAML produces a complete mihomo (Clash Meta) YAML subscription
// config: typed proxies, PROXY/AUTO groups, optional WARP relay chain, ru
// routing rules and split DNS. XHTTP/mKCP transports are filtered out.
func FormatClashYAML(entries []rename.RenamedEntry, meta FormatMetadata) []byte {
	return FormatClashYAMLWithOptions(entries, meta, ClashOptions{Warp: true, Profile: RoutingProfileRussia})
}

func FormatClashYAMLWithOptions(entries []rename.RenamedEntry, meta FormatMetadata, options ClashOptions) []byte {
	proxies := []any{}
	names := []string{}
	for _, e := range entries {
		proxy := buildClashProxy(e)
		if proxy == nil {
			continue
		}
		proxies = append(proxies, proxy)
		names = append(names, e.RenamedFragment)
	}

	warpEnabled := options.Warp && len(names) > 0
	final := "PROXY"
	if warpEnabled {
		final = "warp"
	}
	if len(names) == 0 {
		final = "DIRECT"
	}

	if warpEnabled {
		proxies = append(proxies, buildClashWarpProxy())
	}

	groups := []any{}
	if len(names) > 0 {
		groups = append(groups,
			map[string]any{
				"name":     "AUTO",
				"type":     "url-test",
				"url":      "https://www.gstatic.com/generate_204",
				"interval": 600,
				"proxies":  names,
			},
			map[string]any{
				"name":    "PROXY",
				"type":    "select",
				"proxies": append([]string{"AUTO"}, names...),
			},
		)
	}

	config := map[string]any{
		"mixed-port":    7890,
		"allow-lan":     false,
		"mode":          "rule",
		"log-level":     "warning",
		"unified-delay": true,
		"geodata-mode":  true,
		"dns":           buildClashDNS(options.Profile, final),
		"proxies":       proxies,
		"proxy-groups":  groups,
		"rules":         buildClashRules(options.Profile, final),
	}

	result, _ := yaml.Marshal(config)
	return result
}

func buildClashWarpProxy() map[string]any {
	return map[string]any{
		"name":         "warp",
		"type":         "wireguard",
		"server":       strings.Split(warp.Endpoint, ":")[0],
		"port":         2408,
		"ip":           strings.Split(warp.Address, "/")[0],
		"private-key":  warp.SecretKey,
		"public-key":   warp.PublicKey,
		"allowed-ips":  []string{"0.0.0.0/0", "::/0"},
		"mtu":          1280,
		"udp":          true,
		"dialer-proxy": "PROXY",
	}
}

func buildClashProxy(entry rename.RenamedEntry) map[string]any {
	r := entry.Record
	qp := r.QueryParams

	proxy := map[string]any{
		"name":   entry.RenamedFragment,
		"server": r.Host,
		"port":   r.Port,
	}

	switch r.Protocol {
	case parse.VLESS:
		proxy["type"] = "vless"
		proxy["uuid"] = r.UUIDOrPassword
		if flow := qp["flow"]; flow != "" {
			proxy["flow"] = flow
		}
	case parse.VMess:
		proxy["type"] = "vmess"
		proxy["uuid"] = r.UUIDOrPassword
		scy := qp["scy"]
		if scy == "" {
			scy = "auto"
		}
		proxy["cipher"] = scy
		proxy["alterId"] = 0
	case parse.Trojan:
		proxy["type"] = "trojan"
		proxy["password"] = r.UUIDOrPassword
	case parse.SS:
		proxy["type"] = "ss"
		method := qp["method"]
		if method == "" {
			method = "aes-256-gcm"
		}
		proxy["cipher"] = method
		proxy["password"] = r.UUIDOrPassword
	case parse.Hysteria2:
		proxy["type"] = "hysteria2"
		proxy["password"] = r.UUIDOrPassword
		if obfs := qp["obfs"]; obfs != "" {
			proxy["obfs"] = obfs
			if pass := qp["obfs-password"]; pass != "" {
				proxy["obfs-password"] = pass
			}
		}
	default:
		return nil
	}
	proxy["udp"] = true

	network, supported := buildClashNetwork(r, proxy)
	if !supported {
		return nil
	}
	if network != "" {
		proxy["network"] = network
	}

	applyClashTLS(r, proxy)
	return proxy
}

// buildClashNetwork maps the share-link transport and fills its options into
// the proxy. supported=false means mihomo has no such transport (xhttp, kcp).
func buildClashNetwork(r parse.ProxyRecord, proxy map[string]any) (string, bool) {
	qp := r.QueryParams
	network := qp["type"]
	if r.Protocol == parse.Hysteria2 {
		return "", true
	}
	switch network {
	case "", "tcp":
		return "", true
	case "ws":
		wsOpts := map[string]any{}
		if path := qp["path"]; path != "" {
			wsOpts["path"] = path
		} else {
			wsOpts["path"] = "/"
		}
		if host := qp["host"]; host != "" {
			wsOpts["headers"] = map[string]any{"Host": host}
		}
		proxy["ws-opts"] = wsOpts
		return "ws", true
	case "grpc":
		grpcOpts := map[string]any{}
		if sn := qp["serviceName"]; sn != "" {
			grpcOpts["grpc-service-name"] = sn
		}
		proxy["grpc-opts"] = grpcOpts
		return "grpc", true
	case "h2", "http":
		h2Opts := map[string]any{}
		if host := qp["host"]; host != "" {
			h2Opts["host"] = []string{host}
		}
		path := qp["path"]
		if path == "" {
			path = "/"
		}
		h2Opts["path"] = []string{path}
		proxy["h2-opts"] = h2Opts
		return "h2", true
	case "httpupgrade":
		huOpts := map[string]any{}
		if path := qp["path"]; path != "" {
			huOpts["path"] = path
		}
		if host := qp["host"]; host != "" {
			huOpts["host"] = host
		}
		proxy["httpupgrade-opts"] = huOpts
		return "httpupgrade", true
	default:
		return "", false
	}
}

func applyClashTLS(r parse.ProxyRecord, proxy map[string]any) {
	qp := r.QueryParams
	security := qp["security"]
	if r.Protocol == parse.Hysteria2 && security == "" {
		security = "tls"
	}
	if security != "tls" && security != "reality" {
		return
	}

	if sni := qp["sni"]; sni != "" {
		if r.Protocol == parse.Trojan || r.Protocol == parse.Hysteria2 {
			proxy["sni"] = sni
		} else {
			proxy["servername"] = sni
		}
	}
	if alpn := qp["alpn"]; alpn != "" {
		proxy["alpn"] = strings.Split(alpn, ",")
	}
	if qp["insecure"] == "1" {
		proxy["skip-cert-verify"] = true
	}

	fp := qp["fp"]
	if fp == "" && security == "reality" {
		fp = "chrome"
	}
	if fp != "" {
		proxy["client-fingerprint"] = fp
	}

	switch r.Protocol {
	case parse.Hysteria2:
		// hysteria2 is always TLS; no extra flag needed
	default:
		proxy["tls"] = true
	}
	if security == "reality" {
		reality := map[string]any{}
		if pbk := qp["pbk"]; pbk != "" {
			reality["public-key"] = pbk
		}
		if sid := qp["sid"]; sid != "" {
			reality["short-id"] = sid
		}
		proxy["reality-opts"] = reality
	}
}

var clashRuGeosites = []string{
	"private",
	"vk",
	"mailru",
	"yandex",
	"category-ru",
	"category-gov-ru",
	"ozon",
	"wildberries",
}

var clashRuDomainSuffixes = []string{
	"loc", "local", "ru", "su", "xn--p1ai", "xn--p1acf", "xn--80asehdb",
	"xn--c1avg", "xn--80aswg", "xn--80adxhks", "moscow", "xn--d1acj3b",
	"kg", "by",
}

func buildClashRules(profile RoutingProfile, final string) []string {
	rules := []string{}
	if profile != RoutingProfileNone {
		rules = append(rules,
			"GEOSITE,category-ads-all,REJECT",
			"GEOSITE,category-ip-geo-detect,REJECT",
			"GEOSITE,torrent,REJECT",
		)
		for _, site := range clashRuGeosites {
			rules = append(rules, "GEOSITE,"+site+",DIRECT")
		}
		for _, suffix := range clashRuDomainSuffixes {
			rules = append(rules, "DOMAIN-SUFFIX,"+suffix+",DIRECT")
		}
		rules = append(rules,
			"DOMAIN-SUFFIX,kontur.host,DIRECT",
			"DOMAIN-SUFFIX,cardlink.link,DIRECT",
			"GEOIP,private,DIRECT,no-resolve",
			"GEOIP,ru,DIRECT",
		)
	} else {
		rules = append(rules, "GEOIP,private,DIRECT,no-resolve")
	}
	return append(rules, "MATCH,"+final)
}

func buildClashDNS(profile RoutingProfile, final string) map[string]any {
	dns := map[string]any{
		"enable":                  true,
		"ipv6":                    false,
		"enhanced-mode":           "fake-ip",
		"fake-ip-range":           "198.18.0.1/16",
		"default-nameserver":      []string{"77.88.8.8", "1.1.1.1"},
		"nameserver":              []string{"https://1.1.1.1/dns-query#" + final},
		"proxy-server-nameserver": []string{"https://77.88.8.8/dns-query"},
	}
	if profile == RoutingProfileNone {
		return dns
	}

	fakeIPFilter := []string{"+.lan", "localhost.ptlogin2.qq.com"}
	for _, suffix := range clashRuDomainSuffixes {
		fakeIPFilter = append(fakeIPFilter, "+."+suffix)
	}
	dns["fake-ip-filter"] = fakeIPFilter

	yandexDoH := []string{"https://77.88.8.8/dns-query"}
	policy := map[string]any{
		"geosite:category-ru,category-gov-ru,ozon,wildberries,yandex,vk,mailru,private": yandexDoH,
	}
	suffixes := make([]string, 0, len(clashRuDomainSuffixes))
	for _, suffix := range clashRuDomainSuffixes {
		suffixes = append(suffixes, "+."+suffix)
	}
	policy[strings.Join(suffixes, ",")] = yandexDoH
	dns["nameserver-policy"] = policy
	return dns
}
