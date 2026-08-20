package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestCheckPlaceLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("db") {
		case "abuseipdb":
			w.Write([]byte(`{"data":{"usageType":"Data Center/Web Hosting/Transit","abuseConfidenceScore":80,"countryCode":"US"}}`))
		case "ip2location":
			w.Write([]byte(`{"usage_type":"DCH","country_code":"US","is_proxy":true,"proxy":{"is_tor":true,"is_vpn":true,"is_data_center":true,"is_spammer":true},"fraud_score":90}`))
		case "ipdata":
			w.Write([]byte(`{"country_code":"US","threat":{"is_proxy":true,"is_datacenter":true,"is_known_abuser":true}}`))
		case "ipqualityscore":
			w.Write([]byte(`{"fraud_score":88,"country_code":"US","proxy":true,"vpn":true,"recent_abuse":true,"bot_status":true}`))
		case "scamalytics":
			w.Write([]byte(`{"external_datasources":{"maxmind_geolite2":{"ip_country_code":"US"},"firehol":{"is_proxy":true},"x4bnet":{"is_tor":true}},"scamalytics":{"scamalytics_proxy":{"is_vpn":true,"is_datacenter":true},"is_blacklisted_external":true,"scamalytics_score":70}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cp := NewCheckPlace(&http.Client{Timeout: time.Second})
	cp.endpoint = server.URL
	result, ok := cp.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("check.place lookup failed")
	}
	if !result.Proxy || !result.VPN || !result.Tor || !result.Abuser || !result.Datacenter || !result.Crawler {
		t.Fatalf("flags = %+v", result)
	}
	if result.RiskScore != 90 {
		t.Fatalf("score = %v, want 90", result.RiskScore)
	}
	if result.Type != TypeHosting {
		t.Fatalf("type = %s, want hosting", result.Type)
	}
	if result.CountryCode != "US" {
		t.Fatalf("country = %s, want US", result.CountryCode)
	}
}

func TestParseAbuseIPDB(t *testing.T) {
	body := []byte(`{"data":{"usageType":"Mobile ISP","abuseConfidenceScore":25,"countryCode":"DE"}}`)
	result, ok := parseAbuseIPDB(body)
	if !ok {
		t.Fatal("parse failed")
	}
	if result.Type != TypeMobile {
		t.Fatalf("type = %s, want mobile", result.Type)
	}
	if result.RiskScore != 25 {
		t.Fatalf("score = %v, want 25", result.RiskScore)
	}
}

func TestParseIP2Location(t *testing.T) {
	body := []byte(`{"usage_type":"ISP","country_code":"DE","proxy":{"is_vpn":true,"is_data_center":false},"fraud_score":33}`)
	result, ok := parseIP2Location(body)
	if !ok {
		t.Fatal("parse failed")
	}
	if result.Type != TypeResidential {
		t.Fatalf("type = %s, want residential", result.Type)
	}
	if !result.VPN {
		t.Fatal("vpn = false, want true")
	}
	if result.RiskScore != 33 {
		t.Fatalf("score = %v, want 33", result.RiskScore)
	}
}

func TestParseIPQS(t *testing.T) {
	body := []byte(`{"fraud_score":85,"country_code":"US","proxy":true,"vpn":false,"recent_abuse":true}`)
	result, ok := parseIPQS(body)
	if !ok {
		t.Fatal("parse failed")
	}
	if result.RiskScore != 85 {
		t.Fatalf("score = %v, want 85", result.RiskScore)
	}
	if !result.Proxy || !result.Abuser {
		t.Fatalf("flags = %+v", result)
	}
}

func TestParseScamalytics(t *testing.T) {
	body := []byte(`{"external_datasources":{"maxmind_geolite2":{"ip_country_code":"US"},"firehol":{"is_proxy":true}},"scamalytics":{"scamalytics_score":65}}`)
	result, ok := parseScamalytics(body)
	if !ok {
		t.Fatal("parse failed")
	}
	if result.RiskScore != 65 {
		t.Fatalf("score = %v, want 65", result.RiskScore)
	}
	if !result.Proxy {
		t.Fatal("proxy = false, want true")
	}
}
