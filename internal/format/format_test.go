package format

import (
	"strings"
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
	if !strings.Contains(url, "[2001:db8::1]") {
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
	if !strings.Contains(url, "[2001:db8::1]") {
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
	if !strings.Contains(url, "[2001:db8::1]") {
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
	if strings.Contains(url, "pass:word@") {
		t.Fatalf("password with colon should be encoded, got %s", url)
	}
}

func TestReconstructVlessPasswordEncoding(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.VLESS,
		Host:           "example.com",
		Port:           443,
		UUIDOrPassword: "uuid@test",
		QueryParams:    map[string]string{"type": "tcp", "security": "tls"},
	}
	url := reconstructVless(record, "test")
	if strings.Contains(url, "uuid@test@") {
		t.Fatalf("password with @ should be encoded, got %s", url)
	}
}

func TestReconstructSSRawURLEncoding(t *testing.T) {
	record := parse.ProxyRecord{
		Protocol:       parse.SS,
		Host:           "1.2.3.4",
		Port:           8388,
		UUIDOrPassword: "testpass",
		QueryParams:    map[string]string{"method": "aes-256-gcm"},
	}
	url := reconstructSS(record, "test")
	// SIP002 requires no padding (=) in base64 userinfo part
	parts := strings.SplitN(url, "@", 2)
	if strings.Contains(parts[0], "=") {
		t.Fatalf("SIP002 base64 should not have padding, got %s", url)
	}
}