package format

import (
	"encoding/json"
	"strings"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
	"github.com/michael/vless-sub-server/internal/warp"
)

// SingboxOptions selects the policy embedded in a complete sing-box config.
type SingboxOptions struct {
	Warp    bool
	Profile RoutingProfile
}

const singboxGeositeBase = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"
const singboxGeoipBase = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/"

// FormatSingboxJSON produces one complete sing-box 1.12 config containing all
// supported proxies, a selector, route rules and DNS policy. Universal across
// sing-box clients (husi, SFA, sing-box CLI). XHTTP/mKCP transports are
// filtered out because no sing-box core implements them.
func FormatSingboxJSON(entries []rename.RenamedEntry, meta FormatMetadata) []byte {
	return FormatSingboxJSONWithOptions(entries, meta, SingboxOptions{Warp: true, Profile: RoutingProfileRussia})
}

func FormatSingboxJSONWithOptions(entries []rename.RenamedEntry, meta FormatMetadata, options SingboxOptions) []byte {
	outbounds := []any{}
	tags := []string{}
	for _, e := range entries {
		ob := buildSingboxOutbound(e)
		if ob == nil {
			continue
		}
		outbounds = append(outbounds, ob)
		tags = append(tags, e.RenamedFragment)
	}

	warpEndpoint := options.Warp && len(tags) > 0
	catchAll := "proxy"
	if warpEndpoint {
		catchAll = "warp-out"
	}

	if len(tags) > 0 {
		selectorOutbounds := append([]any{"auto"}, stringsToAny(tags)...)
		outbounds = append(outbounds,
			map[string]any{
				"type":      "urltest",
				"tag":       "auto",
				"outbounds": stringsToAny(tags),
				"url":       "https://www.gstatic.com/generate_204",
				"interval":  "10m",
			},
			map[string]any{
				"type":      "selector",
				"tag":       "proxy",
				"outbounds": selectorOutbounds,
				"default":   "auto",
			},
		)
	}
	outbounds = append(outbounds,
		map[string]any{"type": "direct", "tag": "direct"},
	)
	if len(tags) == 0 {
		catchAll = "direct"
	}

	config := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"dns":       buildSingboxDNS(options.Profile, catchAll),
		"inbounds":  buildSingboxInbounds(),
		"outbounds": outbounds,
		"route":     buildSingboxRoute(options.Profile, catchAll, warpEndpoint),
	}
	if warpEndpoint {
		config["endpoints"] = []any{buildSingboxWarpEndpoint()}
	}

	result, _ := json.MarshalIndent(config, "", "  ")
	return result
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for i, v := range values {
		result[i] = v
	}
	return result
}

func buildSingboxInbounds() []any {
	return []any{
		map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.18.0.1/30"},
			"auto_route":   true,
			"strict_route": true,
			"stack":        "mixed",
		},
		map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": 12080,
		},
	}
}

func buildSingboxWarpEndpoint() map[string]any {
	return map[string]any{
		"type":        "wireguard",
		"tag":         "warp-out",
		"address":     []string{warp.Address},
		"private_key": warp.SecretKey,
		"mtu":         1280,
		"peers": []any{map[string]any{
			"address":     strings.Split(warp.Endpoint, ":")[0],
			"port":        2408,
			"public_key":  warp.PublicKey,
			"allowed_ips": []string{"0.0.0.0/0", "::/0"},
		}},
		"detour": "proxy",
	}
}

func buildSingboxOutbound(entry rename.RenamedEntry) map[string]any {
	r := entry.Record
	qp := r.QueryParams

	ob := map[string]any{
		"tag":         entry.RenamedFragment,
		"server":      r.Host,
		"server_port": r.Port,
	}

	switch r.Protocol {
	case parse.VLESS:
		ob["type"] = "vless"
		ob["uuid"] = r.UUIDOrPassword
		if flow := qp["flow"]; flow != "" {
			ob["flow"] = flow
		}
	case parse.VMess:
		ob["type"] = "vmess"
		ob["uuid"] = r.UUIDOrPassword
		scy := qp["scy"]
		if scy == "" {
			scy = "auto"
		}
		ob["security"] = scy
		ob["alter_id"] = 0
	case parse.Trojan:
		ob["type"] = "trojan"
		ob["password"] = r.UUIDOrPassword
	case parse.SS:
		ob["type"] = "shadowsocks"
		method := qp["method"]
		if method == "" {
			method = "aes-256-gcm"
		}
		ob["method"] = method
		ob["password"] = r.UUIDOrPassword
	case parse.Hysteria2:
		ob["type"] = "hysteria2"
		ob["password"] = r.UUIDOrPassword
		if obfs := qp["obfs"]; obfs != "" {
			obfsMap := map[string]any{"type": obfs}
			if pass := qp["obfs-password"]; pass != "" {
				obfsMap["password"] = pass
			}
			ob["obfs"] = obfsMap
		}
	default:
		return nil
	}

	transport, supported := buildSingboxTransport(r)
	if !supported {
		return nil
	}
	if transport != nil {
		ob["transport"] = transport
	}

	if tls := buildSingboxTLS(r); tls != nil {
		ob["tls"] = tls
	}
	return ob
}

// buildSingboxTransport maps the share-link transport to a sing-box V2Ray
// transport. supported=false means no sing-box core implements it (xhttp, kcp).
func buildSingboxTransport(r parse.ProxyRecord) (map[string]any, bool) {
	qp := r.QueryParams
	network := qp["type"]
	if r.Protocol == parse.Hysteria2 {
		return nil, true
	}
	switch network {
	case "", "tcp":
		return nil, true
	case "ws":
		ws := map[string]any{"type": "ws"}
		if path := qp["path"]; path != "" {
			ws["path"] = path
		} else {
			ws["path"] = "/"
		}
		if host := qp["host"]; host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		return ws, true
	case "grpc":
		grpc := map[string]any{"type": "grpc"}
		if sn := qp["serviceName"]; sn != "" {
			grpc["service_name"] = sn
		}
		return grpc, true
	case "h2", "http":
		http := map[string]any{"type": "http"}
		if host := qp["host"]; host != "" {
			http["host"] = []string{host}
		}
		if path := qp["path"]; path != "" {
			http["path"] = path
		}
		return http, true
	case "httpupgrade":
		hu := map[string]any{"type": "httpupgrade"}
		if host := qp["host"]; host != "" {
			hu["host"] = host
		}
		if path := qp["path"]; path != "" {
			hu["path"] = path
		}
		return hu, true
	default:
		// xhttp, splithttp, kcp, quic (non-hysteria2): no sing-box transport.
		return nil, false
	}
}

func buildSingboxTLS(r parse.ProxyRecord) map[string]any {
	qp := r.QueryParams
	security := qp["security"]
	if r.Protocol == parse.Hysteria2 && security == "" {
		security = "tls"
	}
	if security != "tls" && security != "reality" {
		return nil
	}

	tls := map[string]any{"enabled": true}
	if sni := qp["sni"]; sni != "" {
		tls["server_name"] = sni
	}
	if alpn := qp["alpn"]; alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if qp["insecure"] == "1" {
		tls["insecure"] = true
	}

	fp := qp["fp"]
	if fp == "" && security == "reality" {
		fp = "chrome"
	}
	if fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if security == "reality" {
		reality := map[string]any{"enabled": true}
		if pbk := qp["pbk"]; pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := qp["sid"]; sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	return tls
}

func singboxRemoteRuleSet(tag, base string) map[string]any {
	return map[string]any{
		"type":            "remote",
		"tag":             tag,
		"format":          "binary",
		"url":             base + tag + ".srs",
		"download_detour": "proxy",
	}
}

var singboxRuGeosites = []string{
	"geosite-private",
	"geosite-vk",
	"geosite-mailru",
	"geosite-yandex",
	"geosite-category-ru",
	"geosite-category-gov-ru",
	"geosite-ozon",
	"geosite-wildberries",
}

var singboxRuDomainSuffixes = []string{
	".ru", ".su", ".рф", ".xn--p1ai", ".xn--p1acf", ".xn--80asehdb",
	".xn--c1avg", ".xn--80aswg", ".xn--80adxhks", ".moscow", ".xn--d1acj3b",
	".loc", ".local", ".kg", ".by",
}

func buildSingboxRoute(profile RoutingProfile, catchAll string, warpEndpoint bool) map[string]any {
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	route := map[string]any{
		"rules":                 rules,
		"final":                 catchAll,
		"auto_detect_interface": true,
		"default_domain_resolver": map[string]any{
			"server":   domainResolverServer(profile),
			"strategy": "ipv4_only",
		},
	}
	if profile == RoutingProfileNone {
		return route
	}

	rules = append(rules,
		map[string]any{
			"rule_set": []string{"geosite-category-ads-all", "geosite-category-ip-geo-detect"},
			"action":   "reject",
		},
		map[string]any{
			"ip_is_private": true,
			"outbound":      "direct",
		},
		map[string]any{
			"domain_suffix": singboxRuDomainSuffixes,
			"outbound":      "direct",
		},
		map[string]any{
			"domain_suffix": []string{"kontur.host", "cardlink.link"},
			"outbound":      "direct",
		},
		map[string]any{
			"rule_set": singboxRuGeosites,
			"outbound": "direct",
		},
		map[string]any{
			"rule_set": []string{"geoip-ru"},
			"outbound": "direct",
		},
	)
	route["rules"] = rules

	sets := []any{
		singboxRemoteRuleSet("geosite-category-ads-all", singboxGeositeBase),
		singboxRemoteRuleSet("geosite-category-ip-geo-detect", singboxGeositeBase),
		singboxRemoteRuleSet("geoip-ru", singboxGeoipBase),
	}
	for _, tag := range singboxRuGeosites {
		sets = append(sets, singboxRemoteRuleSet(tag, singboxGeositeBase))
	}
	route["rule_set"] = sets
	return route
}

func buildSingboxDNS(profile RoutingProfile, catchAll string) map[string]any {
	cloudflare := map[string]any{
		"type":   "https",
		"tag":    "cloudflare",
		"server": "1.1.1.1",
		"path":   "/dns-query",
		"tls":    map[string]any{"server_name": "cloudflare-dns.com"},
		"detour": catchAll,
	}
	if profile == RoutingProfileNone {
		bootstrap := map[string]any{
			"type":   "https",
			"tag":    "bootstrap",
			"server": "77.88.8.8",
			"path":   "/dns-query",
			"tls":    map[string]any{"server_name": "common.dot.dns.yandex.net"},
			"detour": "direct",
		}
		return map[string]any{
			"servers":  []any{bootstrap, cloudflare},
			"final":    "cloudflare",
			"strategy": "ipv4_only",
		}
	}

	yandex := map[string]any{
		"type":   "https",
		"tag":    "yandex",
		"server": "77.88.8.8",
		"path":   "/dns-query",
		"tls":    map[string]any{"server_name": "common.dot.dns.yandex.net"},
		"detour": "direct",
	}
	return map[string]any{
		"servers":  []any{yandex, cloudflare},
		"final":    "cloudflare",
		"strategy": "ipv4_only",
		"rules": []any{
			map[string]any{
				"rule_set": []string{
					"geosite-category-ru", "geosite-category-gov-ru",
					"geosite-ozon", "geosite-wildberries",
					"geosite-yandex", "geosite-vk", "geosite-mailru",
				},
				"server": "yandex",
			},
			map[string]any{
				"domain_suffix": []string{".ru", ".su", ".рф", ".xn--p1ai"},
				"server":        "yandex",
			},
		},
	}
}

func domainResolverServer(profile RoutingProfile) string {
	if profile == RoutingProfileNone {
		return "bootstrap"
	}
	return "yandex"
}
