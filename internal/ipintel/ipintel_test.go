package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestMergeResidentialClean(t *testing.T) {
	results := []Result{
		{Source: "ipapi.is"},
		{Source: "ipinfo", Type: TypeResidential},
	}
	intel := merge(results, netip.MustParseAddr("8.8.8.8"))
	if intel.Type != TypeResidential {
		t.Fatalf("type = %s, want residential", intel.Type)
	}
	if intel.RiskLevel != RiskClean {
		t.Fatalf("risk = %s, want clean", intel.RiskLevel)
	}
	if intel.RiskScore != 0 {
		t.Fatalf("score = %v, want 0", intel.RiskScore)
	}
	if len(intel.Sources) != 2 {
		t.Fatalf("sources = %v, want 2", intel.Sources)
	}
}

func TestMergeHostingSuspicious(t *testing.T) {
	results := []Result{
		{Source: "ipapi.is", Type: TypeHosting, Datacenter: true},
	}
	intel := merge(results, netip.MustParseAddr("8.8.8.8"))
	if intel.Type != TypeHosting {
		t.Fatalf("type = %s, want hosting", intel.Type)
	}
	if intel.RiskLevel != RiskSuspicious {
		t.Fatalf("risk = %s, want suspicious", intel.RiskLevel)
	}
	if intel.RiskScore != 10 {
		t.Fatalf("score = %v, want 10", intel.RiskScore)
	}
}

func TestMergeAbuserRisky(t *testing.T) {
	results := []Result{
		{Source: "ipapi.is", Abuser: true, Tor: true},
	}
	intel := merge(results, netip.MustParseAddr("8.8.8.8"))
	if intel.RiskLevel != RiskRisky {
		t.Fatalf("risk = %s, want risky", intel.RiskLevel)
	}
	if intel.RiskScore != 75 {
		t.Fatalf("score = %v, want 75", intel.RiskScore)
	}
}

func TestCacheLookup(t *testing.T) {
	cache := newCache(time.Minute)
	cache.set("1.2.3.4", Intel{IP: "1.2.3.4", Type: TypeHosting})
	intel, ok := cache.get("1.2.3.4")
	if !ok || intel.Type != TypeHosting {
		t.Fatalf("cache miss or wrong intel: %+v", intel)
	}
	if _, ok := cache.get("5.6.7.8"); ok {
		t.Fatal("unknown ip should be cache miss")
	}
}

func TestIPAPIISLookup(t *testing.T) {
	body := `{"ip":"8.8.8.8","is_datacenter":true,"is_proxy":false,"is_vpn":true,"is_abuser":true,"is_tor":false,"is_crawler":false,"asn":{"asn":15169,"org":"Google LLC","type":"hosting"},"company":{"name":"Google LLC","type":"hosting","abuser_score":"0.25 (High)"},"location":{"country_code":"US","city":"Mountain View"}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "https://ipapi.is" {
			t.Errorf("missing Origin header")
		}
		w.Write([]byte(body))
	}))
	defer server.Close()
	p := newIPAPIIS(time.Second)
	p.endpoint = server.URL
	result, ok := p.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("lookup failed")
	}
	if result.ASN != "AS15169" {
		t.Fatalf("asn = %s, want AS15169", result.ASN)
	}
	if !result.Datacenter || !result.VPN || !result.Abuser {
		t.Fatalf("flags = %+v", result)
	}
	if !result.HasScore || result.RiskScore != 25 {
		t.Fatalf("score = %v, want 25", result.RiskScore)
	}
	if result.Type != TypeHosting {
		t.Fatalf("type = %s, want hosting", result.Type)
	}
}

func TestIPinfoDemoLookup(t *testing.T) {
	body := `{"data":{"city":"Mountain View","country":"US","org":"AS15169 Google LLC","asn":{"asn":"AS15169","name":"Google LLC","type":"hosting"},"company":{"name":"Google LLC","type":"hosting"},"privacy":{"vpn":false,"proxy":false,"tor":false,"hosting":true},"is_mobile":false,"is_hosting":true}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	p := newIPinfoDemo(time.Second)
	p.endpoint = server.URL
	result, ok := p.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("lookup failed")
	}
	if result.ASN != "AS15169" {
		t.Fatalf("asn = %s, want AS15169", result.ASN)
	}
	if !result.Datacenter {
		t.Fatalf("datacenter = false, want true")
	}
	if result.Type != TypeHosting {
		t.Fatalf("type = %s, want hosting", result.Type)
	}
}

func TestIPAPILookup(t *testing.T) {
	body := `{"status":"success","countryCode":"US","city":"Ashburn","isp":"Google LLC","org":"Google Public DNS","as":"AS15169 Google LLC","mobile":false,"proxy":false,"hosting":true}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	p := newIPAPI(time.Second)
	p.endpoint = server.URL
	result, ok := p.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("lookup failed")
	}
	if result.ASN != "AS15169" {
		t.Fatalf("asn = %s, want AS15169", result.ASN)
	}
	if !result.Datacenter {
		t.Fatalf("datacenter = false, want true")
	}
	if result.Type != TypeHosting {
		t.Fatalf("type = %s, want hosting", result.Type)
	}
}

func TestIPSBLookup(t *testing.T) {
	body := `{"asn":15169,"isp":"Google","organization":"Google","country_code":"US","city":"Mountain View","region":"California"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	p := newIPSB(time.Second)
	p.endpoint = server.URL
	result, ok := p.Lookup(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("lookup failed")
	}
	if result.ASN != "AS15169" {
		t.Fatalf("asn = %s, want AS15169", result.ASN)
	}
	if result.CountryCode != "US" {
		t.Fatalf("country = %s, want US", result.CountryCode)
	}
}
