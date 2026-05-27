# xray JSON Output Format Design

**Goal:** Add `?format=json` query parameter to `GET /` endpoint that returns a complete xray-core JSON config with outbounds and routing rules using v2ray/xray syntax.

**Architecture:** New `xrayjson.go` formatter in `internal/format/` maps `ProxyRecord` → xray outbound objects with `protocol`/`settings`/`streamSettings`. Each proxy outbound is chained through a per-proxy WARP outbound (Cloudflare Wireguard) so exit IP is WARP. `handleSub` in `main.go` parses `format` query param and dispatches to the appropriate formatter. Routing rules are hardcoded constants.

**Tech Stack:** Go stdlib `encoding/json`, existing `parse.ProxyRecord` and `rename.RenamedEntry` types.

---

## Endpoint Behavior

`GET /` (or `GET /sub`):

| Query param            | Response Content-Type          | Output                                    |
|------------------------|--------------------------------|-------------------------------------------|
| (none) or `format=url` | `text/plain; charset=utf-8`   | Current base64 URL list (unchanged)       |
| `format=json`          | `application/json; charset=utf-8` | xray-core JSON config                |
| other value            | 400 Bad Request                | `{"error": "unsupported format: <value>, use 'url' or 'json'"}` |

## WARP Chain Architecture

Each proxy gets a per-proxy WARP outbound. Traffic flow:

```
app → warp-out-N (wireguard, dialerProxy=proxy-N) → proxy-N → internet
```

Exit IP = Cloudflare WARP.

### WARP Outbound Template

```json
{
  "tag": "warp-out-N",
  "protocol": "wireguard",
  "settings": {
    "address": ["172.16.0.2/32", "2606:4700:110:87f3:6e1e:cb18:8fb0:8d33/128"],
    "mtu": 1280,
    "peers": [
      {
        "endpoint": "engage.cloudflareclient.com:2408",
        "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "preSharedKey": ""
      }
    ],
    "secretKey": "KGRrQBayYNRfVU8iecN8VmUF5bgOQ3wmJXOscg53LFM="
  },
  "streamSettings": {
    "sockopt": {
      "dialerProxy": "proxy-N"
    }
  }
}
```

WARP credentials (secretKey, peers) are hardcoded constants obtained via `wgcf register`. The `reserved` field is omitted — it is tied to a specific key pair and breaks with different credentials. The `publicKey` is Cloudflare's static server key. The `secretKey` must be refreshed via wgcf when expired. Each proxy outbound (tag `proxy-N`) gets a corresponding WARP outbound (tag `warp-out-N`) with `dialerProxy` pointing to that proxy.

### Routing with WARP

Default outbound = first `warp-out-1`. When no routing rule matches, traffic goes through warp-out-1 → proxy-1.

## JSON Output Structure

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "block",
        "domain": [
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
          "domain:mmg.whatsapp.net"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:category-ru",
          "geosite:private"
        ],
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "domain:kontur.host",
          "domain:cardlink.link"
        ],
        "domain_suffix": [
          ".kg"
        ]
      }
    ]
  },
  "outbounds": [
    {
      "protocol": "vless",
      "tag": "proxy-1",
      "settings": {
        "vnext": [{
          "address": "1.2.3.4",
          "port": 443,
          "users": [{
            "id": "uuid-here",
            "encryption": "none",
            "flow": "xtls-rprx-vision"
          }]
        }]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "serverName": "example.com",
          "fingerprint": "chrome",
          "publicKey": "pbk-value",
          "shortId": "sid-value"
        }
      }
    },
    {
      "tag": "warp-out-1",
      "protocol": "wireguard",
      "settings": {
        "address": ["172.16.0.2/32", "2606:4700:110:87f3:6e1e:cb18:8fb0:8d33/128"],
        "mtu": 1280,
        "peers": [{"endpoint": "engage.cloudflareclient.com:2408", "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "preSharedKey": ""}],
        "secretKey": "KGRrQBayYNRfVU8iecN8VmUF5bgOQ3wmJXOscg53LFM="
      },
      "streamSettings": {"sockopt": {"dialerProxy": "proxy-1"}}
    },
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ]
}
```

Rules are ordered: block → direct (private IP + RU geosite) → direct (specific domains) → first warp-out-N (proxy-default). Xray routes top-to-bottom, first match wins. When no rule matches, traffic goes to the first outbound (warp-out-1, which chains through proxy-1 via WARP).

## ProxyRecord → xray Mapping

### Protocol Mapping

| `ProxyRecord.Protocol` | `protocol` field | settings fields          |
|------------------------|-----------------|--------------------------|
| `vless`               | `"vless"`       | `address`, `port`, `id`, `encryption`, `flow` |
| `vmess`               | `"vmess"`       | `address`, `port`, `id`, `security` |
| `trojan`              | `"trojan"`      | `address`, `port`, `password` |
| `ss`                  | `"shadowsocks"` | `address`, `port`, `method`, `password` |
| `hysteria2`           | `"hysteria2"`   | `address`, `port`, `password` |

### Common Fields

| ProxyRecord field      | xray path                           | Notes                                   |
|------------------------|--------------------------------------|-----------------------------------------|
| `Host`                 | `settings.address`                   |                                         |
| `Port`                 | `settings.port`                      |                                         |
| `RenamedFragment`      | `tag`                                | From `rename.RenamedEntry`              |

### VLESS-Specific

| QueryParam          | xray path                         | Notes                                   |
|---------------------|-----------------------------------|-----------------------------------------|
| `encryption`        | `settings.encryption`            | Required. If empty/`"none"` → `"none"`. PQ string preserved as-is. |
| `flow`              | `settings.flow`                  | e.g. `xtls-rprx-vision`                 |

### VMess-Specific

| QueryParam          | xray path                         | Notes                                   |
|---------------------|-----------------------------------|-----------------------------------------|
| `scy`               | `settings.security`              | Default `"auto"` if empty               |
| `aid`               | `settings.alterId`              | Default 0 if absent                     |

### Shadowsocks-Specific

| QueryParam          | xray path                         | Notes                                   |
|---------------------|-----------------------------------|-----------------------------------------|
| `method`            | `settings.method`                | Default `"aes-256-gcm"`                 |
| `UUIDOrPassword`    | `settings.password`              |                                         |

### Hysteria2-Specific

| QueryParam          | xray path                         | Notes                                   |
|---------------------|-----------------------------------|-----------------------------------------|
| `obfs`              | `streamSettings.hysteriaSettings.obfs.type` | Only `"salamander"`           |
| `obfs-password`     | `streamSettings.hysteriaSettings.obfs.password` |                           |
| `auth`              | `settings.password`              | Hysteria2 auth string                   |

### streamSettings Mapping

Every outbound (except SS with no transport) gets a `streamSettings` block:

```json
{
  "network": "ws",
  "security": "tls",
  "wsSettings": { ... },
  "tlsSettings": { ... }
}
```

### Transport Mapping (`QueryParams["type"]` → `streamSettings.network`)

| `type` value    | `network` value  | settings key                                                    |
|----------------|------------------|-----------------------------------------------------------------|
| `ws`           | `"websocket"`    | `wsSettings: {path, host, headers}`                             |
| `grpc`         | `"grpc"`         | `grpcSettings: {serviceName, multiMode}`                        |
| `h2` or `http` | `"h2"`           | `httpSettings: {path, host}`                                    |
| `httpupgrade`  | `"httpupgrade"`  | `httpupgradeSettings: {path, host}`                              |
| `kcp`          | `"mkcp"`         | `kcpSettings` (skip if unsupported by target client)            |
| `quic`         | —                | Skip record (xray uses quic only in VLESS transport, not standalone) |
| `tcp` or empty | `"raw"`          | No additional settings block (xray 1.8+ uses `raw`, older uses `tcp`) |

### TLS Mapping (`QueryParams["security"]` → `streamSettings.security`)

| `security` value | `streamSettings.security` | settings key                                           |
|-------------------|--------------------------|---------------------------------------------------------|
| `tls`             | `"tls"`                  | `tlsSettings: {serverName, fingerprint, alpn, allowInsecure}` |
| `reality`         | `"reality"`              | `realitySettings: {serverName, fingerprint, publicKey, shortId}` |
| empty/`none`      | `"none"`                 | No TLS settings block                                  |

### TLS Settings Details

**tlsSettings (security=tls):**
```json
{
  "serverName": "sni-value",
  "fingerprint": "chrome",
  "alpn": ["h2", "http/1.1"],
  "allowInsecure": false
}
```

- `serverName` ← `QueryParams["sni"]`
- `fingerprint` ← `QueryParams["fp"]`
- `alpn` ← `QueryParams["alpn"]` (comma-split → array)
- `allowInsecure` ← `QueryParams["allowInsecure"]` (if `"1"` → true)

**realitySettings (security=reality):**
```json
{
  "serverName": "sni-value",
  "fingerprint": "chrome",
  "publicKey": "pbk-value",
  "shortId": "sid-value"
}
```

- `serverName` ← `QueryParams["sni"]`
- `fingerprint` ← `QueryParams["fp"]` (default `"chrome"`)
- `publicKey` ← `QueryParams["pbk"]`
- `shortId` ← `QueryParams["sid"]` (string, not array)

### WebSocket Settings Details

```json
"wsSettings": {
  "path": "/ws",
  "host": "example.com",
  "headers": {}
}
```

- `path` ← `QueryParams["path"]` (default `"/"`)
- `host` ← `QueryParams["host"]`
- Early data: if path contains `?ed=N`, extract `ed` and set `useBrowserForwarding` or handle via path

### gRPC Settings Details

```json
"grpcSettings": {
  "serviceName": "grpc-service",
  "multiMode": true
}
```

- `serviceName` ← `QueryParams["serviceName"]`
- `multiMode` ← `QueryParams["mode"] == "multi"` → true, else false

### HTTP/2 Settings Details

```json
"httpSettings": {
  "path": "/h2",
  "host": ["example.com"]
}
```

- `path` ← `QueryParams["path"]`
- `host` ← `QueryParams["host"]` (as array)

### HTTPUpgrade Settings Details

```json
"httpupgradeSettings": {
  "path": "/upgrade",
  "host": "example.com"
}
```

- `path` ← `QueryParams["path"]`
- `host` ← `QueryParams["host"]`

## Routing Rules (Hardcoded)

### Block List

Domains blocked for all traffic:

```
geosite:category-ads
domain:max.ru
domain:oneme.ru
domain:ipv4-internet.yandex.net
domain:ipv6-internet.yandex.net
domain:ifconfig.me
domain:api.ipify.org
domain:checkip.amazonaws.com
domain:ip.mail.ru
domain:calls.okcdn.ru
domain:mtalk.google.com
domain:main.telegram.org
domain:mmg.whatsapp.net
```

### Direct List

Domains/IPs routed directly (no proxy):

```
geosite:category-ru
geosite:private
geoip:private
domain:kontur.host
domain:cardlink.link
domain_suffix:.kg
```

Note: `domain:kg` in original list was a ccTLD, not a resolvable domain. Changed to `domain_suffix:.kg` to match all `.kg` domains. `gosuslugi.ru` moved from block to direct (government portal should bypass proxy for RU users).

## Code Structure

### New file: `internal/format/xrayjson.go`

- `FormatXrayJSON(entries []rename.RenamedEntry, meta FormatMetadata) []byte` — produces full JSON config
- `buildOutbound(entry rename.RenamedEntry, index int) map[string]any` — maps single entry to xray outbound object, tag=`proxy-N`
- `buildWarpOutbound(proxyTag string, index int) map[string]any` — builds per-proxy WARP outbound, tag=`warp-out-N`
- `buildStreamSettings(qp map[string]string) map[string]any` — builds streamSettings block
- `buildTLSSettings(security string, qp map[string]string) map[string]any` — builds tlsSettings or realitySettings
- `buildTransportSettings(network string, qp map[string]string) map[string]any` — builds transport-specific settings (wsSettings, grpcSettings, etc.)
- `buildRoutingRules() map[string]any` — returns routing object with hardcoded rules

### Modified file: `cmd/vless-sub-server/main.go`

- Parse `format` query param from request URL
- Dispatch to `format.FormatOutput` (url) or `format.FormatXrayJSON` (json)
- Return 400 for unknown format values
- Set appropriate Content-Type header

## Error Handling

- Unknown `format` value → 400 with JSON error body
- Unsupported transport (quic, xhttp) → skip record (log warning)
- Missing required fields (address, port, uuid) → skip record (shouldn't happen after parse stage)