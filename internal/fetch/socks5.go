package fetch

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// Socks5Transport builds an HTTP transport dialing through a socks5://
// proxy URL (user:pass@host:port supported). Used for sources that require
// a specific egress country, e.g. RU-only subscription hosts.
func Socks5Transport(rawURL string, timeout time.Duration) (*http.Transport, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse socks5 url: %w", err)
	}
	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}

	var auth *proxy.Auth
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		auth = &proxy.Auth{User: parsed.User.Username(), Password: password}
	}
	dialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("build socks5 dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks5 dialer lacks context support")
	}

	return &http.Transport{
		DialContext:           contextDialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}, nil
}
