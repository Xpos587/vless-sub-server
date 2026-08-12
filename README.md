# vless-sub-server

Standalone Go HTTP server that fetches proxy subscriptions, probes exit-IPs through each proxy via xray-core, and serves renamed results.

## Features

- Fetches proxy subscriptions (VLESS, VMess, Trojan, Shadowsocks, Hysteria2)
- Resolves DNS and verifies exit-IPs through xray-core
- Takes five lightweight Cloudflare health samples per proxy, smooths quality
  with EWMA, and publishes the best stable routes first
- Keeps per-proxy `HEALTHY`, `DEGRADED`, `DEAD`, and `RECOVERING` state across
  refreshes; dead entries stay in the recovery probe loop but are not emitted
- Measures a rotating subset of healthy routes with bounded bandwidth downloads
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
      {"tag": "socks", "port": 10808, "protocol": "socks", ...},
      {"tag": "http",  "port": 10809, "protocol": "http", ...}
    ],
    "outbounds": [
      {"tag": "proxy-1", "protocol": "vless", ...},
      {"tag": "warp-out-1", "protocol": "wireguard", "streamSettings": {"sockopt": {"dialerProxy": "proxy-1"}}, ...},
      {"tag": "direct", "protocol": "freedom"},
      {"tag": "block", "protocol": "blackhole"}
    ],
    "routing": {"domainStrategy": "IPIfNonMatch", "rules": [..., {"outboundTag": "warp-out-1", "port": "0-65535"}]},
    "dns": {}
  }
]
```

**Why proxy-N first in outbounds:** v2rayNG detects the proxy type from the first outbound with a known protocol. If wireguard were first, it would show WARP as the profile instead of the actual proxy.

Traffic flow: inbound → routing catch-all rule sends to `warp-out-N` → WARP connects through `proxy-N` via `dialerProxy` → WARP tunnel → destination. v2rayNG imports each element as a separate profile. MahsaNG supports this format via manual import.

## Pipeline

```
fetch → stale-source merge → parse → DNS → xray geo + health samples
  → quality state + EWMA → bounded bandwidth stage → rename → format → atomic cache swap
```

1. **fetch** — concurrent HTTP GET, base64/sing-box JSON decode
2. **parse** — protocol URL → `ProxyRecord`
3. **DNS** — miekg/dns resolve, private IP detection
4. **exit-IP + health probe** — xray-core in-process: one `ipwho.is` geo
   request and five sequential `speed.cloudflare.com/__down?bytes=0` samples
5. **quality** — median latency, loss, jitter, EWMA score, and recovery state
6. **bandwidth** — at most a configured global byte budget, selected before any
   download begins; failed bandwidth measurements are neutral
7. **format + publish** — one ordered snapshot for URL and JSON; an empty or
   systemic-failure refresh never replaces a populated cache

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `REFRESH_INTERVAL` | `30m` | Auto-refresh period |
| `SUBSCRIPTION_URLS` | — | Comma-separated subscription endpoints (required) |
| `HWID` | — | Hardware ID for custom headers (required) |
| `NAME_INCLUDE` | `""` | Include proxies matching fragment |
| `NAME_EXCLUDE` | `""` | Exclude proxies matching fragment |
| `DNS_TIMEOUT` | `2s` | DNS resolve timeout |
| `EXIT_PROBE_TIMEOUT` | `12s` | Exit-IP probe timeout |
| `PROBE_SAMPLE_COUNT` | `5` | Sequential Cloudflare health samples per proxy (1-10) |
| `PROBE_SAMPLE_GAP` | `100ms` | Delay between health samples |
| `PROBE_SAMPLE_TIMEOUT` | `5s` | Timeout per health sample |
| `BANDWIDTH_ENABLED` | `true` | Enable bounded rotating bandwidth probes |
| `BANDWIDTH_BYTES` | `1048576` | Bytes in one bandwidth download (64 KiB-8 MiB) |
| `BANDWIDTH_BUDGET_BYTES` | `33554432` | Hard maximum scheduled download bytes per refresh |
| `BANDWIDTH_TIMEOUT` | `8s` | Timeout per bandwidth probe |
| `BANDWIDTH_REFRESH_AFTER` | `2h` | Minimum age before a successful bandwidth sample is renewed |
| `BANDWIDTH_RETRY_AFTER` | `30m` | Delay before retrying a failed bandwidth sample |
| `SOURCE_STALE_MAX_AGE` | `6h` | Per-source fallback age for timeout, 429, and 5xx failures |
| `MAX_CONCURRENT` | `50` | Concurrency limit |
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
  exitprobe/exitprobe.go        — xray-core integration, exit-IP, geo lookup
  pipeline/pipeline.go          — refresh orchestration and atomic publication policy
  quality/                      — metrics, scoring, state machine, runtime history
  geo/geo.go                    — GeoInfo types
  rename/rename.go              — rename with flag+city+ISP, dedup
  format/format.go              — subscription output with header
  format/xrayjson.go            — per-proxy xray-core JSON config array
```

## License

Private project. All rights reserved.
