package parse

import (
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
