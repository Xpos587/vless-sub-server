package parse

import (
	"encoding/base64"
	"testing"
)

func TestDedupKeyIncludesPassword(t *testing.T) {
	records := []string{
		"vless://uuid1@real-host.com:443?type=tcp&security=tls#A",
		"vless://uuid2@real-host.com:443?type=tcp&security=tls#B",
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
		"vless://uuid1@real-host.com:443?type=tcp&security=tls#A",
		"vless://uuid1@real-host.com:443?type=tcp&security=tls#B",
	}
	result := ParseAllLines(records)
	if len(result.Records) != 1 {
		t.Fatalf("expected 1 record (same UUID), got %d", len(result.Records))
	}
	if result.Duplicates != 1 {
		t.Fatalf("expected 1 duplicate, got %d", result.Duplicates)
	}
}

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
	vmessJSON := `{"v":"2","ps":"test","add":"example.com","port":443,"id":"uuid","net":"tcp","tls":"tls","allowInsecure":true}`
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
