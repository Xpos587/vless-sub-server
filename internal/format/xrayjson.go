package format

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/rename"
)

// WARP credentials — from wgcf registration (refresh when expired)
const (
	warpSecretKey = "KGRrQBayYNRfVU8iecN8VmUF5bgOQ3wmJXOscg53LFM="
	warpPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	warpEndpoint  = "engage.cloudflareclient.com:2408"
	warpAddress   = "172.16.0.2/32"
	warpAddress6  = "2606:4700:110:87f3:6e1e:cb18:8fb0:8d33/128"
)

// FormatXrayJSON produces a JSON array of complete xray-core configs, one per proxy.
// Each config includes: remarks, inbounds (socks+http), outbounds (proxy+warp+direct+block), routing.
// v2rayNG detects JSON config by checking string contains "inbounds" && "outbounds" && "routing".
// It then parses as Array<V2rayConfig> and creates a separate profile per element.
func FormatXrayJSON(entries []rename.RenamedEntry, meta FormatMetadata) []byte {
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
			"remarks":  e.RenamedFragment,
			"log":      map[string]any{"loglevel": "warning"},
			"inbounds":  buildInbounds(i + 1),
			"outbounds": buildPerProxyOutbounds(ob, i+1),
			"routing":   buildRoutingRules(),
			"dns":      map[string]any{},
		}
		configs = append(configs, config)
	}

	result, _ := json.MarshalIndent(configs, "", "  ")
	return result
}

// buildInbounds creates socks and http inbounds for a single proxy config.
// Each proxy gets unique ports so configs can coexist.
func buildInbounds(index int) []any {
	socksPort := 10800 + index
	httpPort := 10800 + 1000 + index
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
// [warp-out-N, proxy-N, direct, block]
// Traffic default route → warp-out-N. WARP endpoint connects through
// proxy-N via dialerProxy, forming the chain: proxy → WARP → destination.
func buildPerProxyOutbounds(proxyOb map[string]any, index int) []any {
	return []any{
		buildWarpOutbound(index),
		proxyOb,
		map[string]any{
			"protocol": "freedom",
			"tag":      "direct",
		},
		map[string]any{
			"protocol": "blackhole",
			"tag":      "block",
		},
	}
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
		ob["protocol"] = "hysteria2"
		ob["settings"] = map[string]any{
			"servers": []any{map[string]any{
				"address":  r.Host,
				"port":     r.Port,
				"password": r.UUIDOrPassword,
			}},
		}

	default:
		return nil
	}

	ss := buildStreamSettings(qp)
	if ss != nil {
		ob["streamSettings"] = ss
	}

	return ob
}

func buildStreamSettings(qp map[string]string) map[string]any {
	security := qp["security"]
	network := qp["type"]

	// Hysteria2: skip streamSettings entirely
	if network == "quic" {
		return nil
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
			"address": []string{warpAddress, warpAddress6},
			"mtu":     1280,
			"peers": []any{map[string]any{
				"endpoint":     warpEndpoint,
				"publicKey":    warpPublicKey,
				"preSharedKey": "",
			}},
			"secretKey": warpSecretKey,
		},
		"streamSettings": map[string]any{
			"sockopt": map[string]any{
				"dialerProxy": fmt.Sprintf("proxy-%d", index),
			},
		},
	}
}

func buildRoutingRules() map[string]any {
	return map[string]any{
		"domainStrategy": "IPIfNonMatch",
		"rules": []any{
			map[string]any{
				"type":        "field",
				"outboundTag": "block",
				"domain": []string{
					"geosite:category-ads",
					"domain:max.ru",
					"domain:oneme.ru",
					"domain:ipv4-internet.yandex.net",
					"domain:ipv6-internet.yandex.net",
					"domain:ifconfig.me",
					"domain:api.ipify.org",
					"domain:checkip.amazonaws.com",
					"domain:ip.mail.ru",
					"domain:calls.okcdn.ru",
					"domain:mtalk.google.com",
					"domain:main.telegram.org",
					"domain:mmg.whatsapp.net",
				},
			},
			map[string]any{
				"type":        "field",
				"outboundTag": "direct",
				"domain": []string{
					"geosite:category-ru",
					"geosite:private",
				},
				"ip": []string{
					"geoip:private",
				},
			},
			map[string]any{
				"type":        "field",
				"outboundTag": "direct",
				"domain": []string{
					"domain:kontur.host",
					"domain:cardlink.link",
				},
				"domain_suffix": []string{
					".kg",
				},
			},
		},
	}
}