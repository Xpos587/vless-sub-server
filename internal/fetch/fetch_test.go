package fetch

import (
	"encoding/json"
	"testing"
)

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