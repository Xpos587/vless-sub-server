# Proxy Parsing & Config Building Correctness Review

> Deep review by 5 specialized agents (opus model) + synthesis. Date: 2026-05-25.

---

## CRITICAL Bugs (must fix)

### C1. Shadowsocks protocol string wrong in xray config
**File**: `internal/exitprobe/exitprobe.go` — `buildOutbound` SS case
**Bug**: `Protocol: string(rec.Protocol)` produces `"ss"`, but xray-core only recognizes `"shadowsocks"`. Every SS proxy causes xray outbound config build to fail silently.
**Fix**:
```go
case parse.SS:
    ob.Protocol = "shadowsocks"
```

### C2. VMess `security` field naming collision
**Files**: `internal/parse/parse.go:165-167`, `internal/exitprobe/exitprobe.go:369`
**Bug**: `QueryParams["security"]` is overloaded — for VLESS it means transport security (tls/reality/none), but for VMess it's passed as the **cipher** in `users[].security`. xray-core expects cipher names (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`), not `"tls"`. Falls through to `AUTO` silently — any explicit VMess cipher is lost.
**Fix**: Parse `scy` from VMess JSON into separate `QueryParams["scy"]`. In `buildOutbound` VMess case, use `"security": rec.QueryParams["scy"]` (default `"auto"`).

### C3. IPv6 brackets missing in URL reconstruction
**File**: `internal/format/format.go` — `reconstructVless`, `reconstructTrojan`, `reconstructSS`
**Bug**: `url.Hostname()` strips `[]` from IPv6. Reconstruction emits `@2001:db8::1:443` — invalid URL. Must be `@[2001:db8::1]:443`.
**Fix** (all three functions):
```go
host := record.Host
if strings.Contains(host, ":") {
    host = "[" + host + "]"
}
```

### C4. Dedup key drops distinct proxies
**File**: `internal/parse/parse.go:67`
**Bug**: `key = host:port:protocol` — proxies with same endpoint but different UUIDs, passwords, or paths are treated as duplicates. Common in load-balanced setups.
**Fix**:
```go
key := record.Host + ":" + strconv.Itoa(record.Port) + ":" + string(record.Protocol) + ":" + record.UUIDOrPassword
```

### C5. Trojan `url.Parse` nil-panic on URL without password
**File**: `internal/parse/parse.go` — `parseTrojan`
**Bug**: `trojan://host:443` → `u.User == nil` → `u.User.Username()` panics.
**Fix**: Add nil guard:
```go
if u.User == nil {
    return nil
}
```

### C6. Trojan password with `:` truncated
**File**: `internal/parse/parse.go` — `parseTrojan`
**Bug**: `url.Parse` splits userinfo on `:`. `trojan://pass:word@host` → `Username()="pass"`, rest lost.
**Fix**: Reconstruct full password:
```go
password := u.User.Username()
if p, ok := u.User.Password(); ok {
    password += ":" + p
}
```

### C7. SIP002 base64 format not handled for Shadowsocks
**File**: `internal/parse/parse.go` — `parseSS`
**Bug**: SIP002: `ss://base64(method:password)@host:port` — parser splits on `@` and `:` directly, base64 part fails at `colonIdx == -1`.
**Fix**: Detect SIP002 — if part before `@` contains no `:`, try base64 decode first.

### C8. VMess port as JSON string causes parse failure
**File**: `internal/parse/parse.go:145-148`
**Bug**: `Port int json:"port"` fails when port is string (`"port": "443"`). Many real-world VMess links encode port as string.
**Fix**: Use `json.Number`:
```go
Port json.Number `json:"port"`
// then:
port, _ := cfg.Port.Int64()
```

---

## MEDIUM Bugs (should fix)

### M1. sing-box uses `transport` not `streamSettings`
**File**: `internal/fetch/fetch.go:406`
**Bug**: `extractSingboxURLs` only checks `outbound["streamSettings"]`. sing-box format uses `transport` key. All sing-box subscriptions lose network/security settings.
**Fix**: Also check `outbound["transport"]`:
```go
stream, _ := outbound["streamSettings"].(map[string]any)
if stream == nil {
    stream, _ = outbound["transport"].(map[string]any)
}
```

### M2. VMess missing fields in parse struct
**File**: `internal/parse/parse.go` — `parseVMess` struct
**Bug**: Missing: `aid` (alterId), `scy` (cipher), `type` (headerType), `alpn`, `fp`, `pbk`, `sid`, `spx` (spiderX), `allowInsecure`.
**Fix**: Expand struct:
```go
var cfg struct {
    Host           string `json:"add"`
    Port           json.Number `json:"port"`
    ID             string `json:"id"`
    PS             string `json:"ps"`
    Net            string `json:"net"`
    Type           string `json:"type"`  // headerType (none/http)
    TLS            string `json:"tls"`
    SNI            string `json:"sni"`
    Path           string `json:"path"`
    Host2          string `json:"host"`
    Flow           string `json:"flow"`
    Aid            json.Number `json:"aid"`
    Scy            string `json:"scy"`
    Alpn           string `json:"alpn"`
    FP             string `json:"fp"`
    PBK            string `json:"pbk"`
    SID            string `json:"sid"`
    SPX            string `json:"spx"`
    AllowInsecure  bool   `json:"allowInsecure"`
}
```

### M3. VMess reconstruction loses fields
**File**: `internal/format/format.go` — `reconstructVMess`
**Bug**: Output JSON loses `flow`, `aid`, `scy`, `alpn`, `fp`, `pbk`, `sid`, `spx`, `type`. Also forces `path: "/"` when original had none.
**Fix**: Only include non-empty fields. Preserve all parsed fields.

### M4. headerType not in xray TCP config
**File**: `internal/exitprobe/exitprobe.go` — `buildStreamSettings`
**Bug**: When `network == "tcp"` and `headerType=http`, `tcpSettings` is omitted. TCP+HTTP camouflage proxies break.
**Fix**:
```go
case "tcp":
    if rec.QueryParams["headerType"] == "http" {
        ss["tcpSettings"] = map[string]any{
            "header": map[string]any{"type": "http"},
        }
    }
```

### M5. Reality `flow` incorrectly placed in `realitySettings`
**File**: `internal/exitprobe/exitprobe.go:439`
**Bug**: `realitySettings` has no `flow` field in xray-core. VLESS `flow` belongs in `users[]` only. Harmless (xray ignores unknown fields) but structurally wrong.
**Fix**: Remove `rs["flow"]` assignment from realitySettings block.

### M6. Missing `spiderX` in realitySettings
**File**: `internal/exitprobe/exitprobe.go:425-442`
**Bug**: `spx` query param not read into reality config.
**Fix**:
```go
if v, ok := rec.QueryParams["spx"]; ok {
    rs["spiderX"] = v
}
```

### M7. sing-box Trojan missing Reality + transport params
**File**: `internal/fetch/fetch.go` — `singboxOutboundToUrl` Trojan case
**Bug**: `pbk`, `sid`, `flow` extracted at top but only added for VLESS. Trojan Reality URLs lose these. Also missing ws/grpc/xhttp transport params for Trojan.
**Fix**: Add `pbk`, `sid` to Trojan params. Replicate transport block from VLESS.

### M8. Password not URL-encoded in reconstruction
**File**: `internal/format/format.go` — `reconstructTrojan`, `reconstructVless`
**Bug**: `fmt.Sprintf("trojan://%s@...")` with password containing `@`, `:`, `#` produces invalid URL.
**Fix**: Use `url.UserPassword(record.UUIDOrPassword, "").String()` for userinfo encoding.

### M9. SS query params / plugins unsupported
**File**: `internal/parse/parse.go` — `parseSS`
**Bug**: SIP002 URLs with `?plugin=obfs-local...` fail parsing — `?plugin=...` included in port string, `strconv.Atoi` fails.
**Fix**: Parse `?` in host portion, extract query params, remove before port parsing.

### M10. Empty query values dropped during parsing
**File**: `internal/parse/parse.go:115`
**Bug**: `if len(v) > 0` drops params like `encryption=` (empty value). This loses the key entirely.
**Fix**: Always store the key:
```go
for k, v := range u.Query() {
    if len(v) > 0 {
        params[k] = v[0]
    } else {
        params[k] = ""
    }
}
```

---

## LOW Bugs (nice to fix)

### L1. Missing `alpn` in TLS settings
**File**: `internal/exitprobe/exitprobe.go` — TLS block
**Fix**:
```go
if v, ok := rec.QueryParams["alpn"]; ok && v != "" {
    ts["alpn"] = strings.Split(v, ",")
}
```

### L2. `normalizeInsecure` not called for VMess/SS
**File**: `internal/parse/parse.go`
**Fix**: Call in `ParseAllLines` after parsing, or in each parser.

### L3. `normalizeInsecure` doesn't handle boolean values
**Bug**: `allowInsecure=true` passes through as `"true"`, not normalized to `"1"`.
**Fix**: Check for `"true"`, `"1"`, `"yes"`.

### L4. Missing `level` field in xray users/servers
**File**: `internal/exitprobe/exitprobe.go`
**Fix**: Add `"level": 0` — cosmetic, defaults to 0 anyway.

### L5. VMess v1 links partially parse
**Fix**: Check `v == "2"` and skip unknown versions.

### L6. Unchecked type assertions in sing-box conversion
**File**: `internal/fetch/fetch.go`
**Bug**: `servers[0].(map[string]any)` can panic on malformed JSON.
**Fix**: Use `ok` guard.

### L7. `alterId: 0` in VMess outbound — unnecessary
**File**: `internal/exitprobe/exitprobe.go`
**Fix**: Remove. xray-core `VMessAccount` doesn't have `alterId`.

### L8. SS base64 uses `URLEncoding` (padded) instead of `RawURLEncoding` (unpadded)
**File**: `internal/format/format.go` — `reconstructSS`
**Bug**: SIP002 spec requires unpadded base64url. Some strict clients may reject padding.
**Fix**: `base64.RawURLEncoding.EncodeToString(...)`.

---

## Impact Summary

| Protocol | Critical | Medium | Low |
|----------|----------|--------|-----|
| **Shadowsocks** | 2 (protocol string, SIP002) | 2 (plugins, base64 padding) | 0 |
| **VMess** | 2 (security collision, port string) | 3 (missing fields, reconstruction, headerType parse) | 3 |
| **Trojan** | 2 (nil panic, password truncation) | 2 (password encoding, sing-box params) | 0 |
| **VLESS** | 1 (IPv6 reconstruction) | 2 (headerType, reality flow) | 2 |
| **General** | 1 (dedup key) | 2 (sing-box transport key, empty values) | 2 |
| **Total** | **8** | **11** | **7** |

---

## Recommended Fix Priority

1. **C1** (SS protocol string) — every SS proxy is broken
2. **C5** (Trojan nil panic) — runtime crash
3. **C6** (Trojan password truncation) — data loss
4. **C2** (VMess security collision) — silent wrong cipher
5. **C4** (dedup key) — silent proxy loss
6. **C8** (VMess port string) — proxy skip
7. **C3** (IPv6) — broken URLs for IPv6 hosts
8. **C7** (SIP002) — SS links from modern providers fail
9. **M1** (sing-box transport key) — all sing-box subs lose settings
10. **M2-M3** (VMess fields) — significant field loss
11. **M7-M8** (sing-box Trojan + password encoding)
12. Rest in order
