package fetch

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestSocks5TransportFetchesThroughProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("vless://uuid@a.example.com:443?security=reality&sni=a.com#node\n"))
	}))
	defer server.Close()

	socksAddr, closeSocks := startMiniSocks5(t)
	defer closeSocks()

	transport, err := Socks5Transport("socks5://testuser:testpass@"+socksAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	results := FetchSubscriptionsVia(context.Background(), []string{server.URL}, 5*time.Second, transport, "socks5")
	if results[0].Status != "ok" || results[0].Via != "socks5" || len(results[0].Lines) != 1 {
		t.Fatalf("result = %+v", results[0])
	}
}

// startMiniSocks5 is a minimal SOCKS5 server (auth + CONNECT) for tests.
func startMiniSocks5(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveMiniSocks5(conn)
		}
	}()
	return listener.Addr().String(), func() { listener.Close() }
}

func serveMiniSocks5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	// greeting
	if _, err := conn.Read(buf); err != nil {
		return
	}
	conn.Write([]byte{5, 2}) // username/password
	n, err := conn.Read(buf) // auth subnegotiation
	if err != nil || n < 5 {
		return
	}
	ulen := int(buf[1])
	user := string(buf[2 : 2+ulen])
	plen := int(buf[2+ulen])
	pass := string(buf[3+ulen : 3+ulen+plen])
	if user != "testuser" || pass != "testpass" {
		conn.Write([]byte{1, 1})
		return
	}
	conn.Write([]byte{1, 0})
	// CONNECT request
	n, err = conn.Read(buf)
	if err != nil || n < 10 || buf[1] != 1 {
		return
	}
	var host string
	switch buf[3] {
	case 1: // IPv4
		host = net.IP(buf[4:8]).String()
	case 3: // domain
		host = string(buf[5 : 5+int(buf[4])])
	case 4: // IPv6
		host = net.IP(buf[4:20]).String()
	}
	port := int(buf[n-2])<<8 | int(buf[n-1])
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() {
		defer conn.Close()
		defer target.Close()
		buf := make([]byte, 32<<10)
		for {
			n, err := target.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	rbuf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(rbuf)
		if n > 0 {
			if _, werr := target.Write(rbuf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

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
