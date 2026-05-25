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