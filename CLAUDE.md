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
fetch → parse → DNS → TCP probe → exit-IP probe (xray) → rename → format
```

1. **fetch** — concurrent HTTP GET on subscription URLs, base64/sing-box JSON decode
2. **parse** — VLESS/VMess/Trojan/SS URL → `ProxyRecord`
3. **DNS** — miekg/dns A-record resolve, retry once, detect private IPs
4. **TCP probe** — dial test, collect latency
5. **exit-IP probe** — xray-core in-process: SOCKS5 inbound per proxy → HTTP GET ipwho.is → fallback CF trace + ip-api.com batch
6. **rename** — `🇩🇪 Frankfurt (ISP)` format, deduplicate names
7. **format** — header with stats + base subscription output; `?format=json` → per-proxy xray-core config array

## Critical Constraints

### JSON format must include `inbounds`
v2rayNG detects xray JSON config via `string.contains("inbounds" && "outbounds" && "routing")`. Output **must** include `inbounds` key or v2rayNG silently skips JSON parsing and falls back to base64/line parsing. Each proxy gets its own config object in the array with `remarks`, `inbounds`, `outbounds`, `routing`.

### VLESS encryption field
xray-core v1.260327.0 supports PQ encryption (`mlkem768x25519plus`). The `encryption` query param **must be preserved** when building xray outbound config — never hardcode `"none"`. If encryption is absent/empty/`"none"`, fallback to `"none"`. This is handled by `vlessEncryption()` in `exitprobe.go`.

### xray-core as library
xray-core is imported as a Go library, not a subprocess. The `core.Instance` is created from JSON config built by `buildCheckConfig()`. Each proxy gets a dedicated SOCKS5 inbound on sequential ports starting at `SOCKS_START_PORT`. Geo dat files (`geosite.dat`, `geoip.dat`) must be at `GEO_DAT_DIR` (set `XRAY_LOCATION_ASSET`).

### Output URL reconstruction
`format.go` reconstructs proxy URLs from `ProxyRecord` + renamed fragment. Query params are preserved as-is. The `encryption` field in output URLs must reflect the original value (not xray's `"none"` probing override).

## Architecture

```
cmd/vless-sub-server/main.go   — HTTP server, pipeline orchestration, caching
internal/
  config/config.go             — env-var config, custom headers, placeholder hosts
  fetch/fetch.go               — subscription fetch + sing-box JSON → URL conversion
  parse/parse.go + types.go   — URL parsing (VLESS/VMess/Trojan/SS), name filter
  dns/dns.go                  — DNS resolution (miekg/dns), private IP detection
  probe/probe.go               — TCP connectivity probe
  exitprobe/exitprobe.go       — xray-core integration, exit-IP detection, geo lookup
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
| `TCP_TIMEOUT` | `3s` | TCP probe timeout |
| `DNS_TIMEOUT` | `2s` | DNS resolve timeout |
| `EXIT_PROBE_TIMEOUT` | `12s` | Exit-IP probe timeout |
| `MAX_CONCURRENT` | `10` | Concurrency limit for probes |
| `SOCKS_START_PORT` | `10801` | First SOCKS5 port for xray |
| `GEO_DAT_DIR` | `/usr/local/share/xray` | Xray geo dat files |

## Endpoints

- `GET /sub` — subscription output (base64 lines with header)
- `GET /sub?format=json` — JSON array of xray-core configs (v2rayNG/MahsaNG compatible)
- `GET /health` — returns `ok`

## JSON Format (`?format=json`)

Returns a JSON array where each element is a complete xray-core config for one proxy. v2rayNG detects this by checking `string.contains("inbounds") && string.contains("outbounds") && string.contains("routing")`, then parses as `Array<V2rayConfig>` — each element becomes a separate profile with `remarks` as the name.

Each config includes:
- `remarks` — proxy name (e.g. `🇩🇪 Frankfurt (ISP)`)
- `inbounds` — socks (port 10800+i) + http (port 11800+i)
- `outbounds` — [proxy-N, warp-out-N, direct, block] with WARP chain via `sockopt.dialerProxy`
- `routing` — block ads, direct for RU/private IPs
- `log`, `dns`

MahsaNG supports JSON config only via manual import (clipboard), not subscription auto-update.

## Critical Constraints
