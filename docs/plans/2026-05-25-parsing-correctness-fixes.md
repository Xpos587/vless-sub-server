# Parsing & Config Correctness Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 8 critical and 11 medium bugs in proxy URL parsing, xray config building, URL reconstruction, and sing-box conversion.

**Architecture:** Fix bugs in dependency order — parse first (source of truth), then config builder, then reconstruction, then sing-box conversion. Each wave produces working, testable code. No refactoring beyond what the bugs require.

**Tech Stack:** Go 1.26, xray-core library, standard library only for tests

---

## File Structure

| File | Changes |
|------|---------|
| `internal/parse/types.go` | Add `HostBrackets` helper, update `ProxyRecord` |
| `internal/parse/parse.go` | Fix Trojan/SS/VMess parsing, dedup key, normalizeInsecure, empty values |
| `internal/parse/parse_test.go` | **Create** — all parsing tests |
| `internal/format/format.go` | Fix IPv6 brackets, VMess reconstruction, SS base64, password encoding |
| `internal/format/format_test.go` | **Create** — all reconstruction tests |
| `internal/exitprobe/exitprobe.go` | Fix SS protocol string, VMess security, reality flow, spiderX, TCP headerType, alpn, alterId |
| `internal/exitprobe/exitprobe_test.go` | **Create** — config builder tests |
| `internal/fetch/fetch.go` | Fix sing-box transport key, Trojan Reality/transport, unchecked assertions |
| `internal/fetch/fetch_test.go` | **Create** — sing-box conversion tests |

---

## Wave 1: Parse Layer (C4, C5, C6, C7, C8, M2, M9, M10, L2, L3, L5)

Parse is the source of truth. All downstream fixes depend on correct data in `ProxyRecord`.

### Task 1: Add `parseHost` helper and fix dedup key (C4)

**Files:**
- Modify: `internal/parse/parse.go`
- Create: `internal/parse/parse_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/parse/parse_test.go
package parse

import "testing"

func TestDedupKeyIncludesPassword(t *testing.T) {
	records := []string{
		"vless://uuid1@example.com:443?type=tcp&security=tls#A",
		"vless://uuid2@example.com:443?type=tcp&security=tls#B",
	}
	result := ParseAllLines(records)
	if len(result.Records) < 2 {
		t.Fatalf("expected 2 records (different UUIDs), got %d", len(result.Records))
	}
	if result.Duplicates != 0 {
		t.Fatalf("expected 0 duplicates, got %d", result.Duplicates)
	}
}

func TestDedupKeySameHostPortProtocolSameUUID(t *testing.T) {
	records := []string{
		"vless://uuid1@example.com:443?type=tcp&security=tls#A",
		"vless://uuid1@example.com:443?type=tcp&security=tls#B",
	}
	result := ParseAllLines(records)
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record (same UUID), got %d", len(result.Records))
	}
	if result.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate, got %d", result.Duplicates)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/parse/ -run TestDedup -v`
Expected: FAIL — two records with same host:port:protocol but different UUIDs are deduped as one

- [ ] **Step 3: Fix dedup key to include UUIDOrPassword**

In `internal/parse/parse.go`, change line 67:

```go
key := record.Host + ":" + strconv.Itoa(record.Port) + ":" + string(record.Protocol) + ":" + record.UUIDOrPassword
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/parse/ -run TestDedup -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parse/parse.go internal/parse/parse_test.go
git commit -m "fix: include UUID/password in dedup key to avoid dropping distinct proxies"
```

---

### Task 2: Fix Trojan parsing — nil guard and password with colon (C5, C6)

**Files:**
- Modify: `internal/parse/parse.go`
- Modify: `internal/parse/parse_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestTrojanNoPasswordNoPanic(t *testing.T) {
	record := parseTrojan("trojan://example.com:443?security=tls")
	if record != nil {
		t.Fatal("expected nil for URL without password")
	}
}

func TestTrojanPasswordWithColon(t *testing.T) {
	record := parseTrojan("trojan://pass:word@example.com:443?security=tls")
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.UUIDOrPassword != "pass:word" {
		t.Fatalf("expected password 'pass:word', got %q", record.UUIDOrPassword)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/parse/ -run TestTrojan -v`
Expected: FAIL — nil dereference panic on first test, truncated password on second

- [ ] **Step 3: Fix `parseTrojan`**

Replace `internal/parse/parse.go` function `parseTrojan` with:

```go
func parseTrojan(line string) *ProxyRecord {
	u, err := url.Parse(line)
	if err != nil {
		return nil
	}
	if u.User == nil {
		return nil
	}
	port := 443
	if p := u.Port(); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	password := u.User.Username()
	if p, ok := u.User.Password(); ok {
		password += ":" + p
	}
	params := map[string]string{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		} else {
			params[k] = ""
		}
	}
	normalizeInsecure(params)

	return &ProxyRecord{
		Protocol:       Trojan,
		Host:           u.Hostname(),
		Port:           port,
		UUIDOrPassword: password,
		QueryParams:    params,
		Fragment:       u.Fragment,
		OriginalLine:   line,
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/parse/ -run TestTrojan -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parse/parse.go internal/parse/parse_test.go
git commit -m "fix: Trojan nil-panic guard and password with colon handling"
```

---

### Task 3: Fix VLESS empty query values + apply normalizeInsecure to all protocols (M10, L2, L3)

**Files:**
- Modify: `internal/parse/parse.go`
- Modify: `internal/parse/parse_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestVLESSPreservesEmptyQueryValue(t *testing.T) {
	record := parseVless("vless://uuid@example.com:443?encryption=&security=tls")
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if _, ok := record.QueryParams["encryption"]; !ok {
		t.Fatal("encryption key missing from QueryParams")
	}
}

func TestNormalizeInsecureBoolean(t *testing.T) {
	params := map[string]string{"allowInsecure": "true"}
	normalizeInsecure(params)
	if params["insecure"] != "1" {
		t.Fatalf("expected insecure=1 for allowInsecure=true, got %q", params["insecure"])
	}
}

func TestVMessNormalizeInsecure(t *testing.T) {
	// VMess URLs parsed from JSON with allowInsecure should also get normalized
	vmessJSON := `{"v":"2","ps":"test","add":"example.com","port":"443","id":"uuid","net":"tcp","tls":"tls","allowInsecure":true}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	line := "vmess://" + encoded
	record := parseVMess(line)
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.QueryParams["insecure"] != "1" {
		t.Fatalf("expected insecure=1 from VMess allowInsecure, got %q", record.QueryParams["insecure"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/parse/ -run "TestVLESSPreserves|TestNormalizeInsecure|TestVMessNormalize" -v`
Expected: FAIL

- [ ] **Step 3: Fix empty values in `parseVless`**

In `parseVless`, replace the params loop:

```go
params := map[string]string{}
for k, v := range u.Query() {
	if len(v) > 0 {
		params[k] = v[0]
	} else {
		params[k] = ""
	}
}
```

- [ ] **Step 4: Fix `normalizeInsecure` to handle boolean values**

Replace `normalizeInsecure`:

```go
func normalizeInsecure(params map[string]string) {
	val := params["allowInsecure"]
	if val == "" {
		val = params["insecure"]
	}
	if val == "" {
		val = params["allow_insecure"]
	}
	if val == "1" || val == "true" || val == "yes" {
		params["insecure"] = "1"
	} else if val != "" {
		params["insecure"] = "1"
	}
	delete(params, "allowInsecure")
	delete(params, "allow_insecure")
}
```

- [ ] **Step 5: Add `normalizeInsecure` call to `parseVMess`**

After building `params` map in `parseVMess`, add:

```go
if cfg.AllowInsecure {
	params["insecure"] = "1"
}
normalizeInsecure(params)
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/parse/ -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add internal/parse/parse.go internal/parse/parse_test.go
git commit -m "fix: preserve empty query values, normalize insecure across all protocols"
```

---

### Task 4: Fix VMess parsing — expand struct, port as string, version check (C8, M2, L5)

**Files:**
- Modify: `internal/parse/parse.go`
- Modify: `internal/parse/parse_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestVMessPortAsString(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"test","add":"example.com","port":"443","id":"uuid","net":"tcp","tls":""}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	line := "vmess://" + encoded
	record := parseVMess(line)
	if record == nil {
		t.Fatal("expected non-nil record for port as string")
	}
	if record.Port != 443 {
		t.Fatalf("expected port 443, got %d", record.Port)
	}
}

func TestVMessMissingFields(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"test","add":"example.com","port":443,"id":"uuid","net":"ws","tls":"tls","sni":"sni.example.com","path":"/ws","host":"ws.example.com","flow":"xtls-rprx-vision","scy":"aes-128-gcm","type":"http","alpn":"h2,http/1.1","fp":"chrome","pbk":"pubkey","sid":"short","spx":"/path"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	line := "vmess://" + encoded
	record := parseVMess(line)
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.QueryParams["scy"] != "aes-128-gcm" {
		t.Fatalf("expected scy=aes-128-gcm, got %q", record.QueryParams["scy"])
	}
	if record.QueryParams["headerType"] != "http" {
		t.Fatalf("expected headerType=http, got %q", record.QueryParams["headerType"])
	}
	if record.QueryParams["alpn"] != "h2,http/1.1" {
		t.Fatalf("expected alpn=h2,http/1.1, got %q", record.QueryParams["alpn"])
	}
	if record.QueryParams["fp"] != "chrome" {
		t.Fatalf("expected fp=chrome, got %q", record.QueryParams["fp"])
	}
	if record.QueryParams["pbk"] != "pubkey" {
		t.Fatalf("expected pbk=pubkey, got %q", record.QueryParams["pbk"])
	}
	if record.QueryParams["sid"] != "short" {
		t.Fatalf("expected sid=short, got %q", record.QueryParams["sid"])
	}
	if record.QueryParams["spx"] != "/path" {
		t.Fatalf("expected spx=/path, got %q", record.QueryParams["spx"])
	}
	if record.QueryParams["flow"] != "xtls-rprx-vision" {
		t.Fatalf("expected flow=xtls-rprx-vision, got %q", record.QueryParams["flow"])
	}
}

func TestVMessV1Rejected(t *testing.T) {
	vmessJSON := `{"v":"1","ps":"test","add":"example.com","port":443,"id":"uuid"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	line := "vmess://" + encoded
	record := parseVMess(line)
	if record != nil {
		t.Fatal("expected nil for VMess v1 link")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/parse/ -run "TestVMessPort|TestVMessMissing|TestVMessV1" -v`
Expected: FAIL

- [ ] **Step 3: Rewrite `parseVMess` with expanded struct**

Replace the entire `parseVMess` function in `internal/parse/parse.go`:

```go
func parseVMess(line string) *ProxyRecord {
	encoded := line[len("vmess://"):]
	encoded = strings.ReplaceAll(encoded, "-", "+")
	encoded = strings.ReplaceAll(encoded, "_", "/")
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}

	var cfg struct {
		V             string `json:"v"`
		Host          string `json:"add"`
		Port          any    `json:"port"`
		ID            string `json:"id"`
		PS            string `json:"ps"`
		Net           string `json:"net"`
		Type          string `json:"type"`
		TLS           string `json:"tls"`
		SNI           string `json:"sni"`
		Path          string `json:"path"`
		Host2         string `json:"host"`
		Flow          string `json:"flow"`
		Aid           any    `json:"aid"`
		Scy           string `json:"scy"`
		Alpn          string `json:"alpn"`
		FP            string `json:"fp"`
		PBK           string `json:"pbk"`
		SID           string `json:"sid"`
		SPX           string `json:"spx"`
		AllowInsecure bool   `json:"allowInsecure"`
	}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil
	}

	if cfg.V != "" && cfg.V != "2" {
		return nil
	}

	// Port can be int or string
	port := 0
	switch p := cfg.Port.(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	case json.Number:
		v, _ := p.Int64()
		port = int(v)
	}

	params := map[string]string{}
	if cfg.Net != "" {
		params["type"] = cfg.Net
	}
	if cfg.TLS == "tls" {
		params["security"] = "tls"
	} else if cfg.TLS == "reality" {
		params["security"] = "reality"
	}
	if cfg.SNI != "" {
		params["sni"] = cfg.SNI
	}
	if cfg.Path != "" {
		params["path"] = cfg.Path
	}
	if cfg.Host2 != "" {
		params["host"] = cfg.Host2
	}
	if cfg.Flow != "" {
		params["flow"] = cfg.Flow
	}
	if cfg.Type != "" && cfg.Type != "none" {
		params["headerType"] = cfg.Type
	}
	if cfg.Scy != "" {
		params["scy"] = cfg.Scy
	}
	if cfg.Alpn != "" {
		params["alpn"] = cfg.Alpn
	}
	if cfg.FP != "" {
		params["fp"] = cfg.FP
	}
	if cfg.PBK != "" {
		params["pbk"] = cfg.PBK
	}
	if cfg.SID != "" {
		params["sid"] = cfg.SID
	}
	if cfg.SPX != "" {
		params["spx"] = cfg.SPX
	}
	if cfg.AllowInsecure {
		params["insecure"] = "1"
	}
	normalizeInsecure(params)

	return &ProxyRecord{
		Protocol:       VMess,
		Host:           cfg.Host,
		Port:           port,
		UUIDOrPassword: cfg.ID,
		QueryParams:    params,
		Fragment:       cfg.PS,
		OriginalLine:   line,
	}
}
```

Add `"encoding/json"` to imports if not already present.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/parse/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parse/parse.go internal/parse/parse_test.go
git commit -m "fix: VMess parse — handle port as string, capture all V2 fields, reject v1"
```

---

### Task 5: Fix SIP002 Shadowsocks parsing + query params (C7, M9)

**Files:**
- Modify: `internal/parse/parse.go`
- Modify: `internal/parse/parse_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestSSIP002Base64(t *testing.T) {
	// SIP002: ss://base64(method:password)@host:port
	creds := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:testpass"))
	line := "ss://" + creds + "@1.2.3.4:8388#test"
	record := parseSS(line)
	if record == nil {
		t.Fatal("expected non-nil record for SIP002 format")
	}
	if record.UUIDOrPassword != "testpass" {
		t.Fatalf("expected password 'testpass', got %q", record.UUIDOrPassword)
	}
	if record.QueryParams["method"] != "aes-256-gcm" {
		t.Fatalf("expected method aes-256-gcm, got %q", record.QueryParams["method"])
	}
}

func TestSSPluginParams(t *testing.T) {
	creds := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:testpass"))
	line := "ss://" + creds + "@1.2.3.4:8388/?plugin=obfs-local%3Bobfs-host%3Dexample.com#test"
	record := parseSS(line)
	if record == nil {
		t.Fatal("expected non-nil record")
	}
	if record.QueryParams["plugin"] == "" {
		t.Fatal("expected plugin param to be captured")
	}
}

func TestSSLegacyBase64(t *testing.T) {
	// Legacy: ss://base64(method:password@host:port)#fragment
	inner := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:testpass@1.2.3.4:8388"))
	line := "ss://" + inner + "#test"
	record := parseSS(line)
	if record == nil {
		t.Fatal("expected non-nil record for legacy format")
	}
	if record.QueryParams["method"] != "aes-256-gcm" {
		t.Fatalf("expected method aes-256-gcm, got %q", record.QueryParams["method"])
	}
}
```

Add `"encoding/base64"` to test file imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/parse/ -run "TestSSIP002|TestSSPlugin|TestSSLegacy" -v`
Expected: FAIL

- [ ] **Step 3: Rewrite `parseSS` with SIP002 and legacy support**

Replace `parseSS` in `internal/parse/parse.go`:

```go
func parseSS(line string) *ProxyRecord {
	encoded := line[len("ss://"):]
	hashIdx := strings.Index(encoded, "#")
	var fragment, main string
	if hashIdx != -1 {
		fragment = encoded[hashIdx+1:]
		main = encoded[:hashIdx]
	} else {
		main = encoded
	}

	// Split query params from host:port part
	var hostPort string
	params := map[string]string{}
	qIdx := strings.Index(main, "?")
	if qIdx != -1 {
		hostPort = main[:qIdx]
		for _, pair := range strings.Split(main[qIdx+1:], "&") {
			eqIdx := strings.Index(pair, "=")
			if eqIdx != -1 {
				params[pair[:eqIdx]] = pair[eqIdx+1:]
			} else {
				params[pair] = ""
			}
		}
		// Trim query from main for @ splitting
		main = main[:qIdx]
	} else {
		hostPort = main
	}

	atIdx := strings.LastIndex(main, "@")
	if atIdx == -1 {
		// Legacy format: entire main is base64(method:password@host:port)
		decoded, err := base64decode(main)
		if err != nil {
			return nil
		}
		innerAt := strings.LastIndex(decoded, "@")
		if innerAt == -1 {
			return nil
		}
		methodPassword := decoded[:innerAt]
		hostPort = decoded[innerAt+1:]
		colonIdx := strings.Index(methodPassword, ":")
		if colonIdx == -1 {
			return nil
		}
		method := methodPassword[:colonIdx]
		password := methodPassword[colonIdx+1:]
		if params == nil {
			params = map[string]string{}
		}
		params["method"] = method
		host, port := splitHostPort(hostPort)
		if host == "" || port == 0 {
			return nil
		}
		return &ProxyRecord{
			Protocol:       SS,
			Host:           host,
			Port:           port,
			UUIDOrPassword: password,
			QueryParams:    params,
			Fragment:       fragment,
			OriginalLine:   line,
		}
	}

	// SIP002 format: base64(method:password)@host:port
	methodPassword := main[:atIdx]
	hostPort = main[atIdx+1:]

	// Try SIP002 base64 decode of credentials
	var method, password string
	if colonIdx := strings.Index(methodPassword, ":"); colonIdx != -1 {
		// Unencoded legacy-style in URL (method:password@host:port)
		method = methodPassword[:colonIdx]
		password = methodPassword[colonIdx+1:]
	} else {
		// SIP002: base64(method:password)
		decoded, err := base64decode(methodPassword)
		if err != nil {
			return nil
		}
		colonIdx := strings.Index(decoded, ":")
		if colonIdx == -1 {
			return nil
		}
		method = decoded[:colonIdx]
		password = decoded[colonIdx+1:]
	}

	if params == nil {
		params = map[string]string{}
	}
	params["method"] = method

	host, port := splitHostPort(hostPort)
	if host == "" || port == 0 {
		return nil
	}

	return &ProxyRecord{
		Protocol:       SS,
		Host:           host,
		Port:           port,
		UUIDOrPassword: password,
		QueryParams:    params,
		Fragment:       fragment,
		OriginalLine:   line,
	}
}

// base64decode tries URL-safe then standard base64 decoding.
func base64decode(s string) (string, error) {
	// Try URL-safe unpadded
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(decoded), nil
	}
	// Try URL-safe padded
	s2 := s
	for len(s2)%4 != 0 {
		s2 += "="
	}
	if decoded, err := base64.URLEncoding.DecodeString(s2); err == nil {
		return string(decoded), nil
	}
	// Try standard
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(decoded), nil
	}
	s2 = s
	for len(s2)%4 != 0 {
		s2 += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s2)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// splitHostPort splits host:port handling IPv6 brackets.
func splitHostPort(hostPort string) (string, int) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port — try as host only
		return "", 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}
```

Add `"encoding/base64"` and `"net"` to imports in `parse.go`.

- [ ] **Step 4: Run tests**

Run: `go test ./internal/parse/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/parse/parse.go internal/parse/parse_test.go
git commit -m "fix: SIP002 base64, legacy format, plugin params for Shadowsocks"
```

---

## Wave 2: Xray Config Builder (C1, C2, M4, M5, M6, L1, L7)

### Task 6: Fix SS protocol string and VMess security collision in xray config (C1, C2)

**Files:**
- Modify: `internal/exitprobe/exitprobe.go`
- Create: `internal/exitprobe/exitprobe_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/exitprobe/exitprobe_test.go
package exitprobe

import (
	"encoding/json"
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
)

func TestBuildOutboundSSProtocol(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.SS,
		Host:           "1.2.3.4",
		Port:           8388,
		UUIDOrPassword: "testpass",
		QueryParams:    map[string]string{"method": "aes-256-gcm"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	if ob.Protocol != "shadowsocks" {
		t.Fatalf("expected protocol 'shadowsocks', got %q", ob.Protocol)
	}
}

func TestBuildOutboundVMessSecurity(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.VMess,
		Host:           "1.2.3.4",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams:    map[string]string{"scy": "aes-128-gcm", "security": "tls", "type": "ws"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	data, _ := json.Marshal(ob)
	var parsed struct {
		Settings struct {
			Vnext []struct {
				Users []struct {
					Security string `json:"security"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	json.Unmarshal(data, &parsed)
	userSec := parsed.Settings.Vnext[0].Users[0].Security
	if userSec != "aes-128-gcm" {
		t.Fatalf("expected user security 'aes-128-gcm', got %q", userSec)
	}
}

func TestBuildOutboundVMessSecurityDefault(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.VMess,
		Host:           "1.2.3.4",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams:    map[string]string{"security": "tls", "type": "ws"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	data, _ := json.Marshal(ob)
	var parsed struct {
		Settings struct {
			Vnext []struct {
				Users []struct {
					Security string `json:"security"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	json.Unmarshal(data, &parsed)
	userSec := parsed.Settings.Vnext[0].Users[0].Security
	if userSec != "auto" {
		t.Fatalf("expected user security 'auto' (default), got %q", userSec)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/exitprobe/ -run "TestBuildOutbound" -v`
Expected: FAIL — SS protocol is `"ss"` not `"shadowsocks"`, VMess user security is `"tls"` not cipher

- [ ] **Step 3: Fix `buildOutbound` in `exitprobe.go`**

In `buildOutbound`, change the SS case:

```go
	case parse.SS:
		ob.Protocol = "shadowsocks"
		method := rec.QueryParams["method"]
		if method == "" {
			method = "aes-256-gcm"
		}
		ob.Settings = map[string]any{
			"servers": []map[string]any{
				{
					"address":  rec.Host,
					"port":     rec.Port,
					"method":   method,
					"password": rec.UUIDOrPassword,
				},
			},
		}
```

In `buildOutbound`, change the VMess user security field:

```go
	case parse.VMess:
		scy := rec.QueryParams["scy"]
		if scy == "" {
			scy = "auto"
		}
		ob.Settings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": rec.Host,
					"port":    rec.Port,
					"users": []map[string]any{
						{
							"id":       rec.UUIDOrPassword,
							"security": scy,
						},
					},
				},
			},
		}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/exitprobe/ -run "TestBuildOutbound" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/exitprobe/exitprobe.go internal/exitprobe/exitprobe_test.go
git commit -m "fix: SS protocol string shadowsocks, VMess cipher security instead of transport TLS"
```

---

### Task 7: Fix streamSettings — reality flow, spiderX, TCP headerType, alpn (M4, M5, M6, L1)

**Files:**
- Modify: `internal/exitprobe/exitprobe.go`
- Modify: `internal/exitprobe/exitprobe_test.go`

- [ ] **Step 1: Write the failing tests**

```go
func TestBuildStreamSettingsRealityNoFlowInSettings(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "reality", "sni": "example.com", "fp": "chrome", "pbk": "pubkey", "sid": "short", "flow": "xtls-rprx-vision", "spx": "/path"},
	}
	ss := buildStreamSettings(rec)
	rs := ss["realitySettings"].(map[string]any)
	if _, hasFlow := rs["flow"]; hasFlow {
		t.Fatal("flow should NOT be in realitySettings")
	}
	if _, hasSpiderX := rs["spiderX"]; !hasSpiderX {
		t.Fatal("spiderX should be in realitySettings")
	}
	if rs["spiderX"] != "/path" {
		t.Fatalf("expected spiderX=/path, got %v", rs["spiderX"])
	}
}

func TestBuildStreamSettingsTCPHeaderType(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "none", "type": "tcp", "headerType": "http"},
	}
	ss := buildStreamSettings(rec)
	tc, ok := ss["tcpSettings"].(map[string]any)
	if !ok {
		t.Fatal("expected tcpSettings for headerType=http")
	}
	header := tc["header"].(map[string]any)
	if header["type"] != "http" {
		t.Fatalf("expected header type http, got %v", header["type"])
	}
}

func TestBuildStreamSettingsTLSAlpn(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "tls", "type": "tcp", "alpn": "h2,http/1.1"},
	}
	ss := buildStreamSettings(rec)
	ts := ss["tlsSettings"].(map[string]any)
	alpn, ok := ts["alpn"]
	if !ok {
		t.Fatal("expected alpn in tlsSettings")
	}
	alpnArr := alpn.([]string)
	if len(alpnArr) != 2 || alpnArr[0] != "h2" {
		t.Fatalf("expected alpn [h2, http/1.1], got %v", alpnArr)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/exitprobe/ -run "TestBuildStreamSettings" -v`
Expected: FAIL

- [ ] **Step 3: Fix `buildStreamSettings` in `exitprobe.go`**

Replace `buildStreamSettings` with:

```go
func buildStreamSettings(rec parse.ProxyRecord) map[string]any {
	ss := map[string]any{
		"network":  rec.QueryParams["type"],
		"security": rec.QueryParams["security"],
	}

	if ss["network"] == nil {
		ss["network"] = "tcp"
	}
	if ss["security"] == nil {
		ss["security"] = "none"
	}

	network := ss["network"].(string)
	security := ss["security"].(string)

	// Reality settings
	if security == "reality" {
		rs := map[string]any{}
		if v, ok := rec.QueryParams["sni"]; ok {
			rs["serverName"] = v
		}
		if v, ok := rec.QueryParams["fp"]; ok {
			rs["fingerprint"] = v
		}
		if v, ok := rec.QueryParams["pbk"]; ok {
			rs["publicKey"] = v
		}
		if v, ok := rec.QueryParams["sid"]; ok {
			rs["shortId"] = v
		}
		if v, ok := rec.QueryParams["spx"]; ok {
			rs["spiderX"] = v
		}
		ss["realitySettings"] = rs
	} else if security == "tls" {
		ts := map[string]any{}
		if v, ok := rec.QueryParams["sni"]; ok {
			ts["serverName"] = v
		}
		if v, ok := rec.QueryParams["fp"]; ok {
			ts["fingerprint"] = v
		}
		if rec.QueryParams["insecure"] == "1" {
			ts["allowInsecure"] = true
		}
		if v, ok := rec.QueryParams["alpn"]; ok && v != "" {
			ts["alpn"] = strings.Split(v, ",")
		}
		ss["tlsSettings"] = ts
	}

	// Transport settings
	switch network {
	case "tcp":
		if rec.QueryParams["headerType"] == "http" {
			ss["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": "http"},
			}
		}
	case "ws":
		ws := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			ws["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			ws["headers"] = map[string]any{"Host": v}
		}
		ss["wsSettings"] = ws
	case "grpc":
		gs := map[string]any{}
		if v, ok := rec.QueryParams["serviceName"]; ok {
			gs["serviceName"] = v
		}
		if v, ok := rec.QueryParams["mode"]; ok {
			gs["multiMode"] = (v == "multi")
		}
		ss["grpcSettings"] = gs
	case "httpupgrade":
		hu := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			hu["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			hu["host"] = v
		}
		ss["httpupgradeSettings"] = hu
	case "xhttp":
		xh := map[string]any{}
		if v, ok := rec.QueryParams["path"]; ok {
			xh["path"] = v
		}
		if v, ok := rec.QueryParams["host"]; ok {
			xh["host"] = v
		}
		if v, ok := rec.QueryParams["mode"]; ok {
			xh["mode"] = v
		}
		ss["xhttpSettings"] = xh
	}

	return ss
}
```

Add `"strings"` to imports if not present.

- [ ] **Step 4: Remove `alterId` from VMess outbound**

In `buildOutbound`, VMess case — the `alterId: 0` field was already removed in Step 3 of Task 6. Verify it's gone.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/exitprobe/ -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/exitprobe/exitprobe.go internal/exitprobe/exitprobe_test.go
git commit -m "fix: remove flow from realitySettings, add spiderX, TCP headerType, TLS alpn"
```

---

## Wave 3: URL Reconstruction (C3, M3, M8, L8)

### Task 8: Fix IPv6 brackets and password encoding in reconstruction (C3, M8)

**Files:**
- Modify: `internal/format/format.go`
- Create: `internal/format/format_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/format/format_test.go
package format

import (
	"testing"

	"github.com/michael/vless-sub-server/internal/parse"
)

func TestReconstructVlessIPv6(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.VLESS,
		Host:           "2001:db8::1",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams:    map[string]string{"type": "tcp", "security": "tls"},
	}
	url := reconstructVless(record, "test")
	if !contains(url, "[2001:db8::1]") {
		t.Fatalf("expected IPv6 brackets in URL, got %s", url)
	}
}

func TestReconstructTrojanIPv6(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.Trojan,
		Host:           "2001:db8::1",
		Port:           443,
		UUIDOrPassword: "password",
		QueryParams:    map[string]string{"security": "tls"},
	}
	url := reconstructTrojan(record, "test")
	if !contains(url, "[2001:db8::1]") {
		t.Fatalf("expected IPv6 brackets in URL, got %s", url)
	}
}

func TestReconstructSSIPv6(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.SS,
		Host:           "2001:db8::1",
		Port:           8388,
		UUIDOrPassword: "testpass",
		QueryParams:    map[string]string{"method": "aes-256-gcm"},
	}
	url := reconstructSS(record, "test")
	if !contains(url, "[2001:db8::1]") {
		t.Fatalf("expected IPv6 brackets in URL, got %s", url)
	}
}

func TestReconstructTrojanPasswordEncoding(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.Trojan,
		Host:           "example.com",
		Port:           443,
		UUIDOrPassword: "pass:word",
		QueryParams:    map[string]string{"security": "tls"},
	}
	url := reconstructTrojan(record, "test")
	if contains(url, "pass:word@") {
		t.Fatalf("password with colon should be encoded, got %s", url)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

Simplify `contains` — use `strings.Contains`:

```go
import "strings"

// then in tests:
if !strings.Contains(url, "[2001:db8::1]") { ... }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/format/ -v`
Expected: FAIL

- [ ] **Step 3: Add `formatHost` helper and fix all reconstruction functions**

Add helper at top of `format.go`:

```go
func formatHost(host string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
```

Fix `reconstructVless`:

```go
func reconstructVless(record parse.ProxyRecord, fragment string) string {
	params := url.Values{}
	for k, v := range record.QueryParams {
		params.Set(k, v)
	}
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	userinfo := url.User(record.UUIDOrPassword).String()
	return fmt.Sprintf("vless://%s@%s:%d?%s%s", userinfo, formatHost(record.Host), record.Port, params.Encode(), frag)
}
```

Fix `reconstructTrojan`:

```go
func reconstructTrojan(record parse.ProxyRecord, fragment string) string {
	params := url.Values{}
	for k, v := range record.QueryParams {
		params.Set(k, v)
	}
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	userinfo := url.User(record.UUIDOrPassword).String()
	return fmt.Sprintf("trojan://%s@%s:%d?%s%s", userinfo, formatHost(record.Host), record.Port, params.Encode(), frag)
}
```

Fix `reconstructSS`:

```go
func reconstructSS(record parse.ProxyRecord, fragment string) string {
	method := record.QueryParams["method"]
	if method == "" {
		method = "aes-256-gcm"
	}
	userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + record.UUIDOrPassword))
	frag := ""
	if fragment != "" {
		frag = "#" + url.PathEscape(fragment)
	}
	return fmt.Sprintf("ss://%s@%s:%d%s", userInfo, formatHost(record.Host), record.Port, frag)
}
```

Note: `url.User(s)` URL-encodes the string properly for userinfo. For VLESS it's a UUID (safe), for Trojan it's a password (may contain `:`, `@` etc).

- [ ] **Step 4: Run tests**

Run: `go test ./internal/format/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/format/format.go internal/format/format_test.go
git commit -m "fix: IPv6 brackets, password URL-encoding, SS raw base64 in reconstruction"
```

---

### Task 9: Fix VMess reconstruction — preserve all fields (M3)

**Files:**
- Modify: `internal/format/format.go`
- Modify: `internal/format/format_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestReconstructVMessPreservesFields(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.VMess,
		Host:           "example.com",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams: map[string]string{
			"type":        "ws",
			"security":    "tls",
			"sni":         "sni.example.com",
			"path":        "/ws",
			"host":        "ws.example.com",
			"flow":        "xtls-rprx-vision",
			"scy":         "aes-128-gcm",
			"alpn":        "h2,http/1.1",
			"fp":          "chrome",
			"pbk":         "pubkey",
			"sid":         "short",
			"spx":         "/path",
			"headerType":  "http",
		},
	}
	url := reconstructVMess(record, "testnode")
	// Decode and check
	encoded := url[len("vmess://"):]
	encoded = strings.ReplaceAll(encoded, "-", "+")
	encoded = strings.ReplaceAll(encoded, "_", "/")
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	var cfg map[string]any
	json.Unmarshal(decoded, &cfg)

	if cfg["flow"] != "xtls-rprx-vision" {
		t.Fatalf("expected flow, got %v", cfg["flow"])
	}
	if cfg["scy"] != "aes-128-gcm" {
		t.Fatalf("expected scy, got %v", cfg["scy"])
	}
	if cfg["alpn"] != "h2,http/1.1" {
		t.Fatalf("expected alpn, got %v", cfg["alpn"])
	}
	if cfg["fp"] != "chrome" {
		t.Fatalf("expected fp, got %v", cfg["fp"])
	}
	if cfg["pbk"] != "pubkey" {
		t.Fatalf("expected pbk, got %v", cfg["pbk"])
	}
	if cfg["sid"] != "short" {
		t.Fatalf("expected sid, got %v", cfg["sid"])
	}
	if cfg["spx"] != "/path" {
		t.Fatalf("expected spx, got %v", cfg["spx"])
	}
	if cfg["type"] != "http" {
		t.Fatalf("expected type=http (headerType), got %v", cfg["type"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/format/ -run TestReconstructVMessPreserves -v`
Expected: FAIL — most fields missing from output

- [ ] **Step 3: Rewrite `reconstructVMess`**

Replace `reconstructVMess` in `format.go`:

```go
func reconstructVMess(record parse.ProxyRecord, fragment string) string {
	vmConfig := map[string]any{
		"v":    "2",
		"ps":   fragment,
		"add":  record.Host,
		"port": record.Port,
		"id":   record.UUIDOrPassword,
		"net":  record.QueryParams["type"],
		"type": record.QueryParams["headerType"],
		"tls":  "",
		"sni":  record.QueryParams["sni"],
		"path": record.QueryParams["path"],
		"host": record.QueryParams["host"],
	}

	if sec := record.QueryParams["security"]; sec == "tls" || sec == "reality" {
		vmConfig["tls"] = "tls"
	}
	if v := record.QueryParams["flow"]; v != "" {
		vmConfig["flow"] = v
	}
	if v := record.QueryParams["scy"]; v != "" {
		vmConfig["scy"] = v
	}
	if v := record.QueryParams["alpn"]; v != "" {
		vmConfig["alpn"] = v
	}
	if v := record.QueryParams["fp"]; v != "" {
		vmConfig["fp"] = v
	}
	if v := record.QueryParams["pbk"]; v != "" {
		vmConfig["pbk"] = v
	}
	if v := record.QueryParams["sid"]; v != "" {
		vmConfig["sid"] = v
	}
	if v := record.QueryParams["spx"]; v != "" {
		vmConfig["spx"] = v
	}

	// Remove empty fields for clean output
	for k, v := range vmConfig {
		if s, ok := v.(string); ok && s == "" {
			delete(vmConfig, k)
		}
	}

	jsonBytes, _ := json.Marshal(vmConfig)
	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	encoded = strings.TrimRight(encoded, "=")
	return "vmess://" + encoded
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/format/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/format/format.go internal/format/format_test.go
git commit -m "fix: preserve all VMess fields in reconstruction, remove empty fields"
```

---

## Wave 4: sing-box Conversion (M1, M7, L6)

### Task 10: Fix sing-box transport key and unchecked assertions (M1, L6)

**Files:**
- Modify: `internal/fetch/fetch.go`
- Create: `internal/fetch/fetch_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/fetch/fetch_test.go
package fetch

import (
	"encoding/json"
	"testing"
)

func TestExtractSingboxURLsTransportKey(t *testing.T) {
	// sing-box uses "transport" instead of "streamSettings"
	input := ` [{"outbounds":[{"protocol":"vless","tag":"test","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid","encryption":"none"}]}]},"transport":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com"}}}],"remarks":"test"}] `
	var data json.RawMessage = []byte(input)
	urls := extractSingboxURLs(data)
	if len(urls) == 0 {
		t.Fatal("expected at least one URL from sing-box transport format")
	}
	if !containsStr(urls[0], "type=ws") {
		t.Fatalf("expected type=ws in URL, got %s", urls[0])
	}
}

func TestExtractSingboxURLsNullServer(t *testing.T) {
	// Malformed entry with null server should not panic
	input := ` [{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[null]}}],"remarks":"test"}] `
	var data json.RawMessage = []byte(input)
	// Should not panic
	extractSingboxURLs(data)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/fetch/ -v`
Expected: FAIL — `transport` key not checked, null server panics

- [ ] **Step 3: Fix `extractSingboxURLs` in `fetch.go`**

Change the stream extraction line:

```go
stream, _ := outbound["streamSettings"].(map[string]any)
if stream == nil {
	stream, _ = outbound["transport"].(map[string]any)
}
```

- [ ] **Step 4: Fix unchecked type assertions in `singboxOutboundToUrl`**

Add `ok` guards for all `servers[0].(map[string]any)` and `vnext[0].(map[string]any)` patterns. For each protocol case, replace:

```go
// VLESS:
vnext, ok := settings["vnext"].([]any)
if !ok || len(vnext) == 0 {
	return ""
}
server, ok := vnext[0].(map[string]any)
if !ok {
	return ""
}
users, _ := server["users"].([]any)
var uuid string
if len(users) > 0 {
	u, ok := users[0].(map[string]any)
	if ok {
		uuid, _ = u["id"].(string)
		if uuid == "" {
			uuid, _ = u["uuid"].(string)
		}
	}
}

// Trojan:
servers, ok := settings["servers"].([]any)
if !ok || len(servers) == 0 {
	return ""
}
server, ok := servers[0].(map[string]any)
if !ok {
	return ""
}

// Shadowsocks:
servers, ok := settings["servers"].([]any)
if !ok || len(servers) == 0 {
	return ""
}
server, ok := servers[0].(map[string]any)
if !ok {
	return ""
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/fetch/ -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/fetch/fetch.go internal/fetch/fetch_test.go
git commit -m "fix: sing-box transport key, unchecked type assertion guards"
```

---

### Task 11: Fix sing-box Trojan Reality + transport params (M7)

**Files:**
- Modify: `internal/fetch/fetch.go`
- Modify: `internal/fetch/fetch_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSingboxTrojanReality(t *testing.T) {
	input := ` [{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[{"address":"example.com","port":443,"password":"pass"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"sni.example.com","fingerprint":"chrome","publicKey":"pubkey","shortId":"short"}}}],"remarks":"test"}] `
	var data json.RawMessage = []byte(input)
	urls := extractSingboxURLs(data)
	if len(urls) == 0 {
		t.Fatal("expected URL from Trojan Reality")
	}
	u := urls[0]
	if !containsStr(u, "pbk=pubkey") {
		t.Fatalf("expected pbk=pubkey in URL, got %s", u)
	}
	if !containsStr(u, "sid=short") {
		t.Fatalf("expected sid=short in URL, got %s", u)
	}
	if !containsStr(u, "security=reality") {
		t.Fatalf("expected security=reality in URL, got %s", u)
	}
}

func TestSingboxTrojanWS(t *testing.T) {
	input := ` [{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[{"address":"example.com","port":443,"password":"pass"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com"},"wsSettings":{"path":"/ws","headers":{"Host":"ws.example.com"}}}}],"remarks":"test"}] `
	var data json.RawMessage = []byte(input)
	urls := extractSingboxURLs(data)
	if len(urls) == 0 {
		t.Fatal("expected URL from Trojan WS")
	}
	u := urls[0]
	if !containsStr(u, "type=ws") {
		t.Fatalf("expected type=ws in URL, got %s", u)
	}
	if !containsStr(u, "path=%2Fws") {
		t.Fatalf("expected path in URL, got %s", u)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/fetch/ -run "TestSingboxTrojan" -v`
Expected: FAIL — pbk/sid missing, transport params missing for Trojan

- [ ] **Step 3: Fix Trojan case in `singboxOutboundToUrl`**

Replace the Trojan case block with:

```go
	case "trojan":
		servers, ok := settings["servers"].([]any)
		if !ok || len(servers) == 0 {
			return ""
		}
		server, ok := servers[0].(map[string]any)
		if !ok {
			return ""
		}
		password, _ := server["password"].(string)
		address, _ := server["address"].(string)
		port := 443
		if v, ok := server["port"].(float64); ok {
			port = int(v)
		}

		params := url.Values{}
		if security != "" {
			params.Set("security", security)
		}
		if sni != "" {
			params.Set("sni", sni)
		}
		if fp != "" {
			params.Set("fp", fp)
		}
		if pbk != "" {
			params.Set("pbk", pbk)
		}
		if sid != "" {
			params.Set("sid", sid)
		}
		if net != "" && net != "tcp" {
			params.Set("type", net)
		}

		// Transport settings (same as VLESS)
		if xs, ok := stream["xhttpSettings"].(map[string]any); ok {
			if p, ok := xs["path"].(string); ok {
				params.Set("path", p)
			}
			if m, ok := xs["mode"].(string); ok {
				params.Set("mode", m)
			}
			if h, ok := xs["host"].(string); ok {
				params.Set("host", h)
			}
		}
		if ws, ok := stream["wsSettings"].(map[string]any); ok {
			if p, ok := ws["path"].(string); ok {
				params.Set("path", p)
			}
			if h, ok := ws["headers"].(map[string]any); ok {
				if host, ok := h["Host"].(string); ok {
					params.Set("host", host)
				}
			}
		}
		if gs, ok := stream["grpcSettings"].(map[string]any); ok {
			if sn, ok := gs["serviceName"].(string); ok {
				params.Set("serviceName", sn)
			}
			if m, ok := gs["mode"].(string); ok {
				params.Set("mode", m)
			}
		}
		if tc, ok := stream["tcpSettings"].(map[string]any); ok {
			if h, ok := tc["header"].(map[string]any); ok {
				if t, ok := h["type"].(string); ok && t == "http" {
					params.Set("headerType", "http")
				}
			}
		}

		frag := ""
		if remark != "" {
			frag = "#" + url.PathEscape(remark)
		}
		return fmt.Sprintf("trojan://%s@%s:%d?%s%s", password, address, port, params.Encode(), frag)
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/fetch/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/fetch/fetch.go internal/fetch/fetch_test.go
git commit -m "fix: sing-box Trojan Reality + transport params, type assertion guards"
```

---

## Wave 5: Integration Test

### Task 12: Full pipeline roundtrip test

**Files:**
- Create: `internal/parse/integration_test.go`

- [ ] **Step 1: Write integration test**

```go
// internal/parse/integration_test.go
package parse

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestVLESSRoundtrip(t *testing.T) {
	original := "vless://uuid-1234@example.com:443?type=ws&security=tls&sni=sni.example.com&path=%2Fws&host=ws.example.com&fp=chrome&encryption=none#Original"
	record := parseVless(original)
	if record == nil {
		t.Fatal("parse failed")
	}
	// Verify all params survived
	if record.QueryParams["encryption"] != "none" {
		t.Fatalf("encryption lost, got %q", record.QueryParams["encryption"])
	}
	if record.QueryParams["fp"] != "chrome" {
		t.Fatalf("fp lost, got %q", record.QueryParams["fp"])
	}
	if record.QueryParams["path"] != "/ws" {
		t.Fatalf("path lost, got %q", record.QueryParams["path"])
	}
	if record.Fragment != "Original" {
		t.Fatalf("fragment lost, got %q", record.Fragment)
	}
}

func TestVMessRoundtrip(t *testing.T) {
	vmConfig := map[string]any{
		"v": "2", "ps": "test", "add": "example.com", "port": 443,
		"id": "uuid", "net": "ws", "tls": "tls", "sni": "sni.example.com",
		"path": "/ws", "host": "ws.example.com", "flow": "xtls-rprx-vision",
		"scy": "aes-128-gcm", "type": "http", "alpn": "h2,http/1.1",
		"fp": "chrome", "pbk": "pubkey", "sid": "short", "spx": "/spider",
	}
	jsonBytes, _ := json.Marshal(vmConfig)
	encoded := base64.StdEncoding.EncodeToString(jsonBytes)
	line := "vmess://" + encoded
	record := parseVMess(line)
	if record == nil {
		t.Fatal("parse failed")
	}
	if record.QueryParams["scy"] != "aes-128-gcm" {
		t.Fatalf("scy lost, got %q", record.QueryParams["scy"])
	}
	if record.QueryParams["headerType"] != "http" {
		t.Fatalf("headerType lost, got %q", record.QueryParams["headerType"])
	}
	if record.QueryParams["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow lost, got %q", record.QueryParams["flow"])
	}
	if record.QueryParams["spx"] != "/spider" {
		t.Fatalf("spx lost, got %q", record.QueryParams["spx"])
	}
}

func TestTrojanRoundtrip(t *testing.T) {
	original := "trojan://pass%40word@example.com:443?security=tls&sni=sni.example.com&type=ws&path=%2Fws#TestNode"
	record := parseTrojan(original)
	if record == nil {
		t.Fatal("parse failed")
	}
	if !strings.Contains(record.UUIDOrPassword, "@") {
		t.Fatalf("password with @ not preserved, got %q", record.UUIDOrPassword)
	}
	if record.QueryParams["type"] != "ws" {
		t.Fatalf("type lost, got %q", record.QueryParams["type"])
	}
}

func TestSSRoundtrip(t *testing.T) {
	// SIP002 format
	creds := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:testpass"))
	line := "ss://" + creds + "@1.2.3.4:8388#TestNode"
	record := parseSS(line)
	if record == nil {
		t.Fatal("parse failed")
	}
	if record.QueryParams["method"] != "aes-256-gcm" {
		t.Fatalf("method lost, got %q", record.QueryParams["method"])
	}
	if record.UUIDOrPassword != "testpass" {
		t.Fatalf("password lost, got %q", record.UUIDOrPassword)
	}
}

func TestDedupWithDifferentPasswords(t *testing.T) {
	creds1 := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass1"))
	creds2 := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass2"))
	lines := []string{
		"ss://" + creds1 + "@1.2.3.4:8388#A",
		"ss://" + creds2 + "@1.2.3.4:8388#B",
	}
	result := ParseAllLines(lines)
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records (different passwords), got %d", len(result.Records))
	}
}
```

- [ ] **Step 2: Run full test suite**

Run: `go test ./internal/... -v`
Expected: ALL PASS

- [ ] **Step 3: Run full build**

Run: `CGO_ENABLED=0 go build -ldflags="-s -w" -o /dev/null ./cmd/vless-sub-server`
Expected: success

- [ ] **Step 4: Commit**

```bash
git add internal/parse/integration_test.go
git commit -m "test: integration roundtrip tests for all protocols"
```

---

## Spec Coverage Check

| Bug ID | Task | Status |
|--------|------|--------|
| C1 | Task 6 | Covered |
| C2 | Task 6 | Covered |
| C3 | Task 8 | Covered |
| C4 | Task 1 | Covered |
| C5 | Task 2 | Covered |
| C6 | Task 2 | Covered |
| C7 | Task 5 | Covered |
| C8 | Task 4 | Covered |
| M1 | Task 10 | Covered |
| M2 | Task 4 | Covered |
| M3 | Task 9 | Covered |
| M4 | Task 7 | Covered |
| M5 | Task 7 | Covered |
| M6 | Task 7 | Covered |
| M7 | Task 11 | Covered |
| M8 | Task 8 | Covered |
| M9 | Task 5 | Covered |
| M10 | Task 3 | Covered |
| L1 | Task 7 | Covered |
| L2 | Task 3 | Covered |
| L3 | Task 3 | Covered |
| L4 | — | Skipped (cosmetic, no functional impact) |
| L5 | Task 4 | Covered |
| L6 | Task 10 | Covered |
| L7 | Task 6 (verified in Step 4) | Covered |
| L8 | Task 8 | Covered |

**All 8 critical + 11 medium bugs covered.** L4 (level field) skipped — xray-core defaults to 0, no functional impact.
