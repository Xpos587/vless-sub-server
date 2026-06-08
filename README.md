# vless-sub-server

Standalone Go HTTP server that fetches proxy subscriptions, probes exit-IPs through each proxy via xray-core, and serves renamed results.

## Features

- Fetches proxy subscriptions (VLESS, VMess, Trojan, Shadowsocks, Hysteria2)
- Resolves DNS, probes TCP connectivity, verifies exit-IPs via xray-core
- Renames proxies with flag + city + ISP (e.g. `🇩🇪 Frankfurt (Hetzner)`)
- Serves subscription output with header stats
- JSON output for v2rayNG / MahsaNG (xray-core config array)
- Cloudflare WARP chain: traffic routed through proxy → WARP → destination
- Deduplicates proxies by name

## Quick Start

```bash
# Build
CGO_ENABLED=0 go build -ldflags="-s -w" -o vless-sub-server ./cmd/vless-sub-server

# Run (SUBSCRIPTION_URLS is required)
SUBSCRIPTION_URLS="https://example.com/sub1,https://example.com/sub2" ./vless-sub-server
```

### Container (Podman)

```bash
podman build -t vless-sub-server .
podman run \
  -e SUBSCRIPTION_URLS="https://example.com/sub" \
  -e HWID="your-hardware-id" \
  -p 8080:8080 \
  vless-sub-server
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /sub` | Subscription output (base64 lines with header) |
| `GET /sub?format=json` | JSON array of xray-core configs (v2rayNG/MahsaNG) |
| `GET /health` | Health check, returns `ok` |

## JSON Format (`?format=json`)

Returns a JSON array where each element is a complete xray-core config for one proxy:

```json
[
  {
    "remarks": "🇩🇪 Frankfurt (Hetzner)",
    "log": {"loglevel": "warning"},
    "inbounds": [
      {"tag": "socks", "port": 10801, "protocol": "socks", ...},
      {"tag": "http",  "port": 11801, "protocol": "http", ...}
    ],
    "outbounds": [
      {"tag": "proxy-1", "protocol": "vless", ...},
      {"tag": "warp-out-1", "protocol": "wireguard", "streamSettings": {"sockopt": {"dialerProxy": "proxy-1"}}, ...},
      {"tag": "direct", "protocol": "freedom"},
      {"tag": "block", "protocol": "blackhole"}
    ],
    "routing": {"domainStrategy": "IPIfNonMatch", "rules": [...]},
    "dns": {}
  }
]
```

Each proxy gets unique SOCKS/HTTP ports, its own WARP chain outbound, and the full routing config. v2rayNG imports each element as a separate profile. MahsaNG supports this format via manual import.

## Pipeline

```
fetch → parse → DNS → TCP probe → exit-IP probe (xray) → rename → format
```

1. **fetch** — concurrent HTTP GET, base64/sing-box JSON decode
2. **parse** — protocol URL → `ProxyRecord`
3. **DNS** — miekg/dns resolve, private IP detection
4. **TCP probe** — connectivity test, latency measurement
5. **exit-IP probe** — xray-core in-process: SOCKS5 → HTTP GET geo API → geo info
6. **rename** — flag + city + ISP, deduplicate
7. **format** — subscription output or per-proxy JSON config

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `REFRESH_INTERVAL` | `30m` | Auto-refresh period |
| `SUBSCRIPTION_URLS` | — | Comma-separated subscription endpoints (required) |
| `HWID` | — | Hardware ID for custom headers (required) |
| `NAME_INCLUDE` | `""` | Include proxies matching fragment |
| `NAME_EXCLUDE` | `""` | Exclude proxies matching fragment |
| `TCP_TIMEOUT` | `3s` | TCP probe timeout |
| `DNS_TIMEOUT` | `2s` | DNS resolve timeout |
| `EXIT_PROBE_TIMEOUT` | `12s` | Exit-IP probe timeout |
| `MAX_CONCURRENT` | `50` | Concurrency limit |
| `SOCKS_START_PORT` | `10801` | First SOCKS5 port for xray |
| `GEO_DAT_DIR` | `/usr/local/share/xray` | Xray geo dat files |
| `DNS_CACHE_TTL` | `10m` | DNS cache TTL |

## Architecture

```
cmd/vless-sub-server/main.go    — HTTP server, pipeline orchestration, caching
internal/
  config/config.go              — env-var config, custom headers
  fetch/fetch.go                — subscription fetch + sing-box JSON → URL
  parse/parse.go + types.go    — URL parsing (VLESS/VMess/Trojan/SS), name filter
  dns/dns.go                   — DNS resolution, private IP detection
  probe/probe.go                — TCP connectivity probe
  exitprobe/exitprobe.go        — xray-core integration, exit-IP, geo lookup
  geo/geo.go                    — GeoInfo types
  rename/rename.go              — rename with flag+city+ISP, dedup
  format/format.go              — subscription output with header
  format/xrayjson.go            — per-proxy xray-core JSON config array
```

## License

Private project. All rights reserved.