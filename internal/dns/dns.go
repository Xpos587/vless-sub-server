package dns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

type DNSResult struct {
	IP        string
	IsPrivate bool
}

func ResolveHosts(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration) map[string]*DNSResult {
	results := make(map[string]*DNSResult, len(hosts))
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrent)

	for _, h := range hosts {
		h := h
		g.Go(func() error {
			ip, isPrivate := resolveWithRetry(ctx, h, timeout)
			mu.Lock()
			results[h] = &DNSResult{IP: ip, IsPrivate: isPrivate}
			mu.Unlock()
			return nil
		})
	}
	g.Wait()
	return results
}

func resolveWithRetry(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return host, true
		}
		return host, false
	}

	select {
	case <-ctx.Done():
		return "", false
	default:
	}
	if ip, ok := resolveOne(ctx, host, timeout); ok {
		return ip, isPrivateIPStr(ip)
	}
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return "", false
	}
	if ip, ok := resolveOne(ctx, host, timeout); ok {
		return ip, isPrivateIPStr(ip)
	}
	return "", false
}

func resolveOne(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Timeout = timeout
	r, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return "", false
	}

	if len(r.Answer) == 0 {
		return "", false
	}

	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), false
		}
	}
	return "", false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func isPrivateIPStr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return isPrivateIP(ip)
}