package ipintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

const proxyCheckV3Fixture = `{
  "status":"ok",
  "8.8.8.8":{
    "network":{"asn":"AS15169","provider":"Google LLC","organisation":"Level 3","type":"Business"},
    "location":{"country_code":"US","city_name":"Mountain View"},
    "detections":{"proxy":false,"vpn":false,"tor":false,"hosting":false,"compromised":true,"scraper":true,"risk":87}
  }
}`

func TestProxyCheckParsesV3NestedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(proxyCheckV3Fixture))
	}))
	defer server.Close()

	provider := newProxyCheckWithURL([]*http.Client{server.Client()}, time.Second, server.URL)
	result, outcome := provider.LookupDetailed(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if outcome != ProviderSuccess {
		t.Fatalf("outcome = %q", outcome)
	}
	if result.ASN != "AS15169" || result.Organization != "Google LLC" || result.CountryCode != "US" || result.City != "Mountain View" || result.Type != TypeBusiness {
		t.Fatalf("result = %#v", result)
	}
	if !result.Abuser || !result.Crawler || !result.HasScore || result.RiskScore != 87 {
		t.Fatalf("detections = %#v", result)
	}
}

func TestProxyCheckRotatesAfterQuotaResponse(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"status":"denied","message":"daily query limit exceeded"}`))
			return
		}
		_, _ = w.Write([]byte(proxyCheckV3Fixture))
	}))
	defer server.Close()

	provider := newProxyCheckWithURL([]*http.Client{server.Client(), server.Client()}, time.Second, server.URL)
	_, outcome := provider.LookupDetailed(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if outcome != ProviderSuccess || requests.Load() != 2 {
		t.Fatalf("outcome=%q requests=%d", outcome, requests.Load())
	}
}
