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
	alpn := ts["alpn"]
	if alpn == nil {
		t.Fatal("expected alpn in tlsSettings")
	}
	alpnArr := alpn.([]string)
	if len(alpnArr) != 2 || alpnArr[0] != "h2" {
		t.Fatalf("expected alpn [h2, http/1.1], got %v", alpnArr)
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