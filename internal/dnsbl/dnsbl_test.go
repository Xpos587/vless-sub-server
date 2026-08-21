package dnsbl

import (
	"context"
	"net"
	"testing"
	"time"

	"net/netip"
)

func TestClassifyLookupDistinguishesNXDOMAINFromResolverFailure(t *testing.T) {
	if status := classifyLookup(nil, &net.DNSError{IsNotFound: true}); status != StatusClean {
		t.Fatalf("NXDOMAIN status = %q", status)
	}
	if status := classifyLookup(nil, &net.DNSError{IsTimeout: true}); status != StatusUnknown {
		t.Fatalf("timeout status = %q", status)
	}
	if status := classifyLookup([]string{"127.0.0.2"}, nil); status != StatusListed {
		t.Fatalf("listed status = %q", status)
	}
}

func TestCheckIPIPv6Unknown(t *testing.T) {
	lists := []List{{Zone: "zen.spamhaus.org", Name: "Spamhaus"}}
	results := CheckIP(context.Background(), netip.MustParseAddr("2001:4860:4860::8888"), lists, time.Second, 2)
	if len(results) != 1 || results[0].Status != StatusUnknown {
		t.Fatalf("ipv6 result = %+v", results)
	}
}

func TestReverseIPv4(t *testing.T) {
	r, ok := reverseIPv4(netip.MustParseAddr("1.2.3.4"))
	if !ok || r != "4.3.2.1" {
		t.Fatalf("reverse = %s, want 4.3.2.1", r)
	}
}

func TestDefaultLists(t *testing.T) {
	if len(DefaultLists) < 5 {
		t.Fatalf("only %d default lists, want >=5", len(DefaultLists))
	}
}
