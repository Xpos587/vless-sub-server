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