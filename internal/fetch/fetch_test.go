package fetch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestFetchSingleClassifiesEmptySuccessfulResponseAsOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	result := fetchSingle(context.Background(), server.URL, time.Second)
	if result.Status != "ok" || len(result.Lines) != 0 {
		t.Fatalf("result = %#v, want successful empty result", result)
	}
}

func TestExtractSingboxURLsTransportKey(t *testing.T) {
	// sing-box uses "transport" instead of "streamSettings"
	input := `[{"outbounds":[{"protocol":"vless","tag":"test","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid","encryption":"none"}]}]},"transport":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com"}}}],"remarks":"test"}]`
	var data json.RawMessage = []byte(input)
	urls := extractSingboxURLs(data)
	if len(urls) == 0 {
		t.Fatal("expected at least one URL from sing-box transport format")
	}
	if !containsStr(urls[0], "type=ws") {
		t.Fatalf("expected type=ws in URL, got %s", urls[0])
	}
}

func TestExtractXrayVLESSPreservesUserFlow(t *testing.T) {
	input := `[{
		"outbounds":[{"protocol":"vless","tag":"vision","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid","encryption":"none","flow":"xtls-rprx-vision"}]}]},
		"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"sni.example.com","fingerprint":"chrome","publicKey":"pubkey","shortId":"short"}}}]}]`
	urls := extractSingboxURLs(json.RawMessage(input))
	if len(urls) != 1 {
		t.Fatalf("urls = %#v", urls)
	}
	parsed, err := url.Parse(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("flow"); got != "xtls-rprx-vision" {
		t.Fatalf("flow = %q, want xtls-rprx-vision", got)
	}
}

func TestExtractSingboxURLsNullServer(t *testing.T) {
	// Malformed entry with null server should not panic
	input := `[{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[null]}}],"remarks":"test"}]`
	var data json.RawMessage = []byte(input)
	// Should not panic
	extractSingboxURLs(data)
}

func TestSingboxTrojanReality(t *testing.T) {
	input := `[{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[{"address":"example.com","port":443,"password":"pass"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"sni.example.com","fingerprint":"chrome","publicKey":"pubkey","shortId":"short"}}}],"remarks":"test"}]`
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
	input := `[{"outbounds":[{"protocol":"trojan","tag":"test","settings":{"servers":[{"address":"example.com","port":443,"password":"pass"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.com"},"wsSettings":{"path":"/ws","headers":{"Host":"ws.example.com"}}}}],"remarks":"test"}]`
	var data json.RawMessage = []byte(input)
	urls := extractSingboxURLs(data)
	if len(urls) == 0 {
		t.Fatal("expected URL from Trojan WS")
	}
	u := urls[0]
	if !containsStr(u, "type=ws") {
		t.Fatalf("expected type=ws in URL, got %s", u)
	}
	if !containsStr(u, "path=") {
		t.Fatalf("expected path in URL, got %s", u)
	}
}

func TestExtractXrayXHTTPSettingsIntoCompleteShareLink(t *testing.T) {
	input := `[{
		"outbounds":[{"protocol":"vless","tag":"xhttp","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid","encryption":"none"}]}]},
		"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"sni.example.com","publicKey":"pubkey"},
		"xhttpSettings":{"host":"cdn.example.com","path":"/x","mode":"packet-up","headers":{"User-Agent":"Mozilla/5.0"},"xmux":{"maxConcurrency":4},"futureOption":{"enabled":true}}}}]}]`
	urls := extractSingboxURLs(json.RawMessage(input))
	if len(urls) != 1 {
		t.Fatalf("urls = %#v", urls)
	}
	parsed, err := url.Parse(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("type") != "xhttp" || parsed.Query().Get("mode") != "packet-up" {
		t.Fatalf("xHTTP link = %s", urls[0])
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(parsed.Query().Get("extra")), &extra); err != nil {
		t.Fatalf("extra missing or invalid in %s: %v", urls[0], err)
	}
	for _, key := range []string{"headers", "xmux", "futureOption"} {
		if _, ok := extra[key]; !ok {
			t.Fatalf("%s missing from extra %#v", key, extra)
		}
	}
}

func TestExtractXrayVMessXHTTPExtraIsObject(t *testing.T) {
	input := `[{"outbounds":[{"protocol":"vmess","tag":"xhttp","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"uuid"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"sni.example.com"},"xhttpSettings":{"host":"cdn.example.com","path":"/x","mode":"packet-up","xmux":{"maxConcurrency":4},"futureOption":{"enabled":true}}}}]}]`
	urls := extractSingboxURLs(json.RawMessage(input))
	if len(urls) != 1 {
		t.Fatalf("urls = %#v", urls)
	}

	encoded := strings.TrimPrefix(urls[0], "vmess://")
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(decoded, &config); err != nil {
		t.Fatal(err)
	}
	extra, ok := config["extra"].(map[string]any)
	if !ok {
		t.Fatalf("extra = %#v, want JSON object", config["extra"])
	}
	for _, key := range []string{"xmux", "futureOption"} {
		if _, ok := extra[key]; !ok {
			t.Fatalf("%s missing from extra %#v", key, extra)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
