package format

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
	"github.com/michael/vless-sub-server/internal/warp"
	"github.com/michael/vless-sub-server/internal/xhttp"
)

type XrayJSONOptions struct {
	Warp    bool
	Profile RoutingProfile
}

// RoutingProfile selects the policy rules embedded in a complete Xray config.
// It has no representation in a standalone VLESS URL.
type RoutingProfile string

const (
	RoutingProfileRussia RoutingProfile = "ru"
	RoutingProfileNone   RoutingProfile = "none"
)

// FormatXrayJSON produces a JSON array of complete xray-core configs, one per proxy.
// Each config includes: remarks, inbounds (socks+http), outbounds (proxy+warp+direct+block), routing.
// v2rayNG detects JSON config by checking string contains "inbounds" && "outbounds" && "routing".
// It then parses as Array<V2rayConfig> and creates a separate profile per element.
func FormatXrayJSON(entries []rename.RenamedEntry, meta FormatMetadata) []byte {
	return FormatXrayJSONWithOptions(entries, meta, XrayJSONOptions{Warp: true, Profile: RoutingProfileRussia})
}

func FormatXrayJSONWithOptions(entries []rename.RenamedEntry, meta FormatMetadata, options XrayJSONOptions) []byte {
	if len(entries) == 0 {
		result, _ := json.Marshal([]any{})
		return result
	}

	configs := make([]map[string]any, 0, len(entries))

	for i, e := range entries {
		ob := buildOutbound(e, i+1)
		if ob == nil {
			continue
		}

		config := map[string]any{
			"remarks":   e.RenamedFragment,
			"log":       map[string]any{"loglevel": "warning"},
			"inbounds":  buildInbounds(i + 1),
			"outbounds": buildPerProxyOutbounds(ob, i+1, options.Warp),
			"routing":   buildRoutingRules(i+1, options.Warp, options.Profile),
			"dns":       map[string]any{},
		}
		configs = append(configs, config)
	}

	result, _ := json.MarshalIndent(configs, "", "  ")
	return result
}

// buildInbounds creates socks and http inbounds with fixed ports.
// v2rayNG/MahsaNG use fixed ports per profile; unique ports serve no purpose.
func buildInbounds(index int) []any {
	socksPort := 10808
	httpPort := 10809
	return []any{
		map[string]any{
			"tag":      "socks",
			"port":     socksPort,
			"protocol": "socks",
			"settings": map[string]any{
				"auth": "noauth",
				"udp":  true,
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		},
		map[string]any{
			"tag":      "http",
			"port":     httpPort,
			"protocol": "http",
			"settings": map[string]any{},
		},
	}
}

// buildPerProxyOutbounds creates the outbound chain for one proxy:
// [proxy-N, warp-out-N, direct, block]
// v2rayNG's getProxyOutbound() returns the first outbound with a known
// protocol, so proxy-N must come first for correct detection. Traffic is
// routed to warp-out-N via catch-all routing rule. WARP connects through
// proxy-N via dialerProxy → chain: proxy → WARP → destination.
func buildPerProxyOutbounds(proxyOb map[string]any, index int, warpEnabled bool) []any {
	outbounds := []any{proxyOb}
	if warpEnabled {
		outbounds = append(outbounds, buildWarpOutbound(index))
	}
	return append(outbounds,
		map[string]any{
			"protocol": "freedom",
			"tag":      "direct",
		},
		map[string]any{
			"protocol": "blackhole",
			"tag":      "block",
		},
	)
}

func buildOutbound(entry rename.RenamedEntry, index int) map[string]any {
	r := entry.Record
	qp := r.QueryParams

	ob := map[string]any{
		"tag": fmt.Sprintf("proxy-%d", index),
	}

	switch r.Protocol {
	case parse.VLESS:
		ob["protocol"] = "vless"
		enc := qp["encryption"]
		if enc == "" {
			enc = "none"
		}
		user := map[string]any{
			"id":         r.UUIDOrPassword,
			"encryption": enc,
		}
		if flow := qp["flow"]; flow != "" {
			user["flow"] = flow
		}
		ob["settings"] = map[string]any{
			"vnext": []any{map[string]any{
				"address": r.Host,
				"port":    r.Port,
				"users":   []any{user},
			}},
		}

	case parse.VMess:
		ob["protocol"] = "vmess"
		scy := qp["scy"]
		if scy == "" {
			scy = "auto"
		}
		user := map[string]any{
			"id":       r.UUIDOrPassword,
			"security": scy,
			"alterId":  0,
		}
		ob["settings"] = map[string]any{
			"vnext": []any{map[string]any{
				"address": r.Host,
				"port":    r.Port,
				"users":   []any{user},
			}},
		}

	case parse.Trojan:
		ob["protocol"] = "trojan"
		ob["settings"] = map[string]any{
			"servers": []any{map[string]any{
				"address":  r.Host,
				"port":     r.Port,
				"password": r.UUIDOrPassword,
			}},
		}

	case parse.SS:
		ob["protocol"] = "shadowsocks"
		method := qp["method"]
		if method == "" {
			method = "aes-256-gcm"
		}
		ob["settings"] = map[string]any{
			"servers": []any{map[string]any{
				"address":  r.Host,
				"port":     r.Port,
				"method":   method,
				"password": r.UUIDOrPassword,
			}},
		}

	case parse.Hysteria2:
		ob["protocol"] = "hysteria"
		ob["settings"] = map[string]any{
			"address":  r.Host,
			"port":     r.Port,
			"password": r.UUIDOrPassword,
			"version":  2,
		}

	default:
		return nil
	}

	ss := buildStreamSettings(r)
	if ss != nil {
		ob["streamSettings"] = ss
	}

	return ob
}

func buildStreamSettings(r parse.ProxyRecord) map[string]any {
	qp := r.QueryParams
	security := qp["security"]
	network := qp["type"]

	// Hysteria2: network="quic" in URL, xray uses "hysteria"
	if r.Protocol == parse.Hysteria2 {
		if network == "" || network == "quic" {
			network = "hysteria"
		}
		if security == "" {
			security = "tls"
		}
		ss := map[string]any{
			"network":  "hysteria",
			"security": "tls",
		}
		hy := map[string]any{
			"version": 2,
			"auth":    r.UUIDOrPassword,
		}
		if obfs := qp["obfs"]; obfs != "" {
			hy["obfs"] = obfs
		}
		if obfsPass := qp["obfs-password"]; obfsPass != "" {
			hy["obfsPassword"] = obfsPass
		}
		ss["hysteriaSettings"] = hy

		if sni := qp["sni"]; sni != "" {
			ts := map[string]any{"serverName": sni}
			if alpn := qp["alpn"]; alpn != "" {
				ts["alpn"] = strings.Split(alpn, ",")
			}
			ss["tlsSettings"] = ts
		}
		if fp := qp["fp"]; fp != "" {
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]any{}
			}
			ss["tlsSettings"].(map[string]any)["fingerprint"] = fp
		}
		if qp["insecure"] == "1" {
			if _, ok := ss["tlsSettings"]; !ok {
				ss["tlsSettings"] = map[string]any{}
			}
			ss["tlsSettings"].(map[string]any)["allowInsecure"] = true
		}
		return ss
	}

	if network == "" {
		network = "tcp"
	}

	// Map transport type to xray network name
	xrayNetwork := mapTransport(network)
	if xrayNetwork == "" {
		return nil // unsupported transport
	}

	ss := map[string]any{
		"network":  xrayNetwork,
		"security": mapSecurity(security),
	}

	ts := buildTransportSettings(xrayNetwork, qp)
	if ts != nil {
		key := xrayTransportKey(xrayNetwork)
		ss[key] = ts
	}

	tls := buildTLSSettings(security, qp)
	if tls != nil {
		key := tlsSettingsKey(security)
		ss[key] = tls
	}

	return ss
}

func mapTransport(t string) string {
	switch t {
	case "ws":
		return "websocket"
	case "grpc":
		return "grpc"
	case "h2", "http":
		return "h2"
	case "httpupgrade":
		return "httpupgrade"
	case "xhttp", "splithttp":
		return "xhttp"
	case "kcp":
		return "mkcp"
	case "tcp":
		return "raw"
	default:
		return ""
	}
}

func mapSecurity(s string) string {
	switch s {
	case "tls":
		return "tls"
	case "reality":
		return "reality"
	default:
		return "none"
	}
}

func xrayTransportKey(network string) string {
	switch network {
	case "websocket":
		return "wsSettings"
	case "grpc":
		return "grpcSettings"
	case "h2":
		return "httpSettings"
	case "httpupgrade":
		return "httpupgradeSettings"
	case "xhttp":
		return "xhttpSettings"
	case "mkcp":
		return "kcpSettings"
	default:
		return ""
	}
}

func buildTransportSettings(network string, qp map[string]string) map[string]any {
	switch network {
	case "websocket":
		ws := map[string]any{}
		if path := qp["path"]; path != "" {
			ws["path"] = path
		} else {
			ws["path"] = "/"
		}
		if host := qp["host"]; host != "" {
			ws["host"] = host
		}
		ws["headers"] = map[string]any{}
		return ws

	case "grpc":
		gs := map[string]any{}
		if sn := qp["serviceName"]; sn != "" {
			gs["serviceName"] = sn
		}
		if mode := qp["mode"]; mode == "multi" {
			gs["multiMode"] = true
		} else {
			gs["multiMode"] = false
		}
		return gs

	case "h2":
		hs := map[string]any{}
		if path := qp["path"]; path != "" {
			hs["path"] = path
		}
		if host := qp["host"]; host != "" {
			hs["host"] = []string{host}
		}
		return hs

	case "httpupgrade":
		hu := map[string]any{}
		if path := qp["path"]; path != "" {
			hu["path"] = path
		}
		if host := qp["host"]; host != "" {
			hu["host"] = host
		}
		return hu

	case "xhttp":
		settings, err := xhttp.SettingsFromParams(qp)
		if err != nil {
			return nil
		}
		return settings

	default:
		return nil
	}
}

func tlsSettingsKey(security string) string {
	switch security {
	case "tls":
		return "tlsSettings"
	case "reality":
		return "realitySettings"
	default:
		return ""
	}
}

func buildTLSSettings(security string, qp map[string]string) map[string]any {
	switch security {
	case "tls":
		tls := map[string]any{}
		if sni := qp["sni"]; sni != "" {
			tls["serverName"] = sni
		}
		if fp := qp["fp"]; fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := qp["alpn"]; alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if qp["insecure"] == "1" {
			tls["allowInsecure"] = true
		}
		return tls

	case "reality":
		rl := map[string]any{}
		if sni := qp["sni"]; sni != "" {
			rl["serverName"] = sni
		}
		fp := qp["fp"]
		if fp == "" {
			fp = "chrome"
		}
		rl["fingerprint"] = fp
		if pbk := qp["pbk"]; pbk != "" {
			rl["publicKey"] = pbk
		}
		if sid := qp["sid"]; sid != "" {
			rl["shortId"] = sid
		}
		return rl

	default:
		return nil
	}
}

func buildWarpOutbound(index int) map[string]any {
	return map[string]any{
		"tag":      fmt.Sprintf("warp-out-%d", index),
		"protocol": "wireguard",
		"settings": map[string]any{
			"address": []string{warp.Address},
			"mtu":     1280,
			"peers": []any{map[string]any{
				"endpoint":     warp.Endpoint,
				"publicKey":    warp.PublicKey,
				"preSharedKey": "",
			}},
			"secretKey": warp.SecretKey,
		},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{
				"dialerProxy": fmt.Sprintf("proxy-%d", index),
			},
		},
	}
}

func buildRoutingRules(index int, warpEnabled bool, profile RoutingProfile) map[string]any {
	catchAllTag := fmt.Sprintf("proxy-%d", index)
	if warpEnabled {
		catchAllTag = fmt.Sprintf("warp-out-%d", index)
	}
	rules := []any{}
	if profile != RoutingProfileNone {
		rules = append(rules,
			map[string]any{
				"type":        "field",
				"outboundTag": "block",
				"domain": []string{
					"geosite:category-ads",
				},
			},
			map[string]any{
				"type":        "field",
				"outboundTag": "direct",
				"domain": []string{
					"geosite:private",
					"geosite:vk",
					"geosite:mailru",
					"geosite:yandex",
					"geosite:category-ru",
					"geosite:category-gov-ru",
					"domain:kontur.host",
					"domain:kg",
					"domain:by",
					"domain:cardlink.link",
					"regexp:^([\\w\\-\\.]+\\.)loc$",
					"regexp:^([\\w\\-\\.]+\\.)local$",
					"regexp:^([\\w\\-\\.]+\\.)ru$",
					"regexp:^([\\w\\-\\.]+\\.)su$",
					"regexp:^([\\w\\-\\.]+\\.)xn--p1ai$",
					"regexp:^([\\w\\-\\.]+\\.)xn--p1acf$",
					"regexp:^([\\w\\-\\.]+\\.)xn--80asehdb$",
					"regexp:^([\\w\\-\\.]+\\.)xn--c1avg$",
					"regexp:^([\\w\\-\\.]+\\.)xn--80aswg$",
					"regexp:^([\\w\\-\\.]+\\.)xn--80adxhks$",
					"regexp:^([\\w\\-\\.]+\\.)moscow$",
					"regexp:^([\\w\\-\\.]+\\.)xn--d1acj3b$",
				},
			},
			map[string]any{
				"type":        "field",
				"outboundTag": "direct",
				"ip": []string{
					"geoip:private",
					"geoip:ru",
				},
			},
		)
	}
	rules = append(rules,
		map[string]any{
			"type":        "field",
			"outboundTag": catchAllTag,
			"port":        "0-65535",
		},
	)
	return map[string]any{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}
