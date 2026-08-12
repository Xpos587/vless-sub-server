# vless-sub-server

Standalone Go HTTP server that fetches proxy subscriptions, probes exit-IPs through each proxy via xray-core, and serves renamed results at `GET /sub`.

## Build & Run

```bash
# Build
CGO_ENABLED=0 go build -ldflags="-s -w" -o vless-sub-server ./cmd/vless-sub-server

# Run
./vless-sub-server
# Custom config via env vars
PORT=8080 REFRESH_INTERVAL=30m SUBSCRIPTION_URLS="url1,url2" ./vless-sub-server
```

Container (podman):
```bash
podman build -t vless-sub-server .
podman run -e PORT=8080 -p 8080:8080 vless-sub-server
```

## Pipeline

```
fetch → stale-source merge → parse → DNS → xray geo + health samples
  → quality state + EWMA → bounded bandwidth stage → rename → format → atomic cache swap
```

1. **fetch** — concurrent HTTP GET on subscription URLs, base64/sing-box JSON decode
2. **parse** — VLESS/VMess/Trojan/SS URL → `ProxyRecord`
3. **DNS** — miekg/dns A-record resolve, retry once, detect private IPs
4. **exit-IP + health probe** — xray-core in-process: `ipwho.is` plus five
   sequential Cloudflare health samples per proxy
5. **quality** — median latency, loss, jitter, EWMA score, and recovery state
6. **bandwidth** — rotating, preselected routes only; bounded by a global byte budget
7. **format + publish** — URL and JSON share one ordered snapshot; empty or
   systemic-failure refreshes never replace a populated cache

## Critical Constraints

### JSON format must include `inbounds`
v2rayNG detects xray JSON config via `string.contains("inbounds" && "outbounds" && "routing")`. Output **must** include `inbounds` key or v2rayNG silently skips JSON parsing and falls back to base64/line parsing. Each proxy gets its own config object in the array with `remarks`, `inbounds`, `outbounds`, `routing`.

### VLESS encryption field
xray-core v1.260327.0 supports PQ encryption (`mlkem768x25519plus`). The `encryption` query param **must be preserved** when building xray outbound config — never hardcode `"none"`. If encryption is absent/empty/`"none"`, fallback to `"none"`. This is handled by `vlessEncryption()` in `exitprobe.go`.

### xray-core as library
xray-core is imported as a Go library, not a subprocess. The `core.Instance` is created from JSON config built by `buildCheckConfig()`. Geo dat files (`geosite.dat`, `geoip.dat`) must be at `GEO_DAT_DIR` (set `XRAY_LOCATION_ASSET`).

### Output URL reconstruction
`format.go` reconstructs proxy URLs from `ProxyRecord` + renamed fragment. Query params are preserved as-is. The `encryption` field in output URLs must reflect the original value (not xray's `"none"` probing override).

## Architecture

```
cmd/vless-sub-server/main.go   — HTTP server and composition root
internal/
  config/config.go             — env-var config, custom headers, placeholder hosts
  fetch/fetch.go               — subscription fetch + sing-box JSON → URL conversion
  parse/parse.go + types.go   — URL parsing (VLESS/VMess/Trojan/SS), name filter
  dns/dns.go                  — DNS resolution (miekg/dns), private IP detection
  exitprobe/exitprobe.go       — xray-core integration, exit-IP detection, geo lookup
  pipeline/pipeline.go         — refresh orchestration and publication policy
  quality/                     — metrics, scoring, state machine, runtime history
  geo/geo.go                   — GeoInfo/IPWhoisResponse types
  rename/rename.go             — rename with flag+city+ISP, dedup
  format/format.go             — output formatting with header + URL reconstruction
  format/xrayjson.go           — per-proxy xray-core JSON config array (v2rayNG format)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `REFRESH_INTERVAL` | `30m` | Auto-refresh period |
| `SUBSCRIPTION_URLS` | (comma-separated) | Subscription endpoints |
| `NAME_INCLUDE` / `NAME_EXCLUDE` | `""` | Filter proxies by fragment |
| `DNS_TIMEOUT` | `2s` | DNS resolve timeout |
| `EXIT_PROBE_TIMEOUT` | `12s` | Exit-IP probe timeout |
| `PROBE_SAMPLE_COUNT` | `5` | Sequential health samples per proxy (1-10) |
| `PROBE_SAMPLE_GAP` | `100ms` | Delay between health samples |
| `PROBE_SAMPLE_TIMEOUT` | `5s` | Timeout per health sample |
| `BANDWIDTH_ENABLED` | `true` | Enable bounded rotating bandwidth probes |
| `BANDWIDTH_BYTES` | `1048576` | Bytes per bandwidth download |
| `BANDWIDTH_BUDGET_BYTES` | `33554432` | Hard scheduled download budget per refresh |
| `BANDWIDTH_TIMEOUT` | `8s` | Timeout per bandwidth probe |
| `BANDWIDTH_REFRESH_AFTER` | `2h` | Re-sample interval after bandwidth success |
| `BANDWIDTH_RETRY_AFTER` | `30m` | Retry interval after bandwidth failure |
| `SOURCE_STALE_MAX_AGE` | `6h` | Per-source timeout/429/5xx fallback age |
| `MAX_CONCURRENT` | `50` | Concurrency limit for probes |
| `GEO_DAT_DIR` | `/usr/local/share/xray` | Xray geo dat files |

## Endpoints

- `GET /sub` — subscription output (base64 lines with header)
- `GET /sub?format=json` — JSON array of xray-core configs (v2rayNG/MahsaNG compatible)
- `GET /health` — returns `ok`

## JSON Format (`?format=json`)

Returns a JSON array where each element is a complete xray-core config for one proxy. v2rayNG detects this by checking `string.contains("inbounds") && string.contains("outbounds") && string.contains("routing")`, then parses as `Array<V2rayConfig>` — each element becomes a separate profile with `remarks` as the name.

Each config includes:
- `remarks` — proxy name (e.g. `🇩🇪 Frankfurt (ISP)`)
- `inbounds` — socks (port 10808) + http (port 10809)
- `outbounds` — [proxy-N, warp-out-N, direct, block] with WARP chain via `sockopt.dialerProxy`
- `routing` — block ads, direct for RU/private IPs, catch-all → warp-out-N (port 0-65535)
- `log`, `dns`

**Why proxy-N first in outbounds:** v2rayNG's `getProxyOutbound()` returns the first outbound with a known protocol (vless, vmess, trojan, etc.). If wireguard were first, v2rayNG would show the WARP config as the "proxy" instead of the actual proxy.

**Traffic flow:** inbound → routing catch-all rule sends to `warp-out-N` → WARP endpoint connects through `proxy-N` via `dialerProxy` → WARP tunnel → destination.

MahsaNG supports JSON config only via manual import (clipboard), not subscription auto-update.

## Critical Constraints
