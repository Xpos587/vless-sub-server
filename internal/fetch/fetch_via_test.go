package fetch

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSubscriptionsViaUsesInjectedTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://uuid@a.example.com:443?security=reality&sni=a.com#node\n"))
	}))
	defer server.Close()

	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}}

	results := FetchSubscriptionsVia(context.Background(), []string{"http://unreachable.invalid/sub"}, 5*time.Second, transport, "proxy")
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	result := results[0]
	if result.Status != "ok" || result.Via != "proxy" {
		t.Fatalf("result = %+v", result)
	}
	if len(result.Lines) != 1 {
		t.Fatalf("lines = %v", result.Lines)
	}
}

func TestFetchSubscriptionsDefaultsViaDirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://uuid@a.example.com:443?security=reality&sni=a.com#node\n"))
	}))
	defer server.Close()

	results := FetchSubscriptions(context.Background(), []string{server.URL}, 5*time.Second)
	if results[0].Status != "ok" || results[0].Via != "" {
		t.Fatalf("result = %+v", results[0])
	}
}
