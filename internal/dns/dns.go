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
	Host      string
	IP        string
	IsPrivate bool
}

type cacheEntry struct {
	ip        string
	isPrivate bool
	expiresAt time.Time
}

type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

func NewDNSCache(ttl time.Duration) *DNSCache {
	return &DNSCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

func (c *DNSCache) Get(host string) (ip string, isPrivate bool, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, exists := c.entries[host]
	if !exists || time.Now().After(e.expiresAt) {
		return "", false, false
	}
	return e.ip, e.isPrivate, true
}

func (c *DNSCache) Set(host, ip string, isPrivate bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[host] = cacheEntry{
		ip:        ip,
		isPrivate: isPrivate,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *DNSCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for host, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, host)
		}
	}
}

func ResolveHosts(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration, cache *DNSCache) map[string]*DNSResult {
	results := make(map[string]*DNSResult, len(hosts))
	var mu sync.Mutex

	var uncached []string
	for _, h := range hosts {
		if cache != nil {
			if ip, isPrivate, ok := cache.Get(h); ok {
				results[h] = &DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}
				continue
			}
		}
		uncached = append(uncached, h)
	}

	if len(uncached) == 0 {
		return results
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrent)

	for _, h := range uncached {
		h := h
		g.Go(func() error {
			ip, isPrivate := resolveWithRetry(ctx, h, timeout)
			mu.Lock()
			results[h] = &DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}
			if cache != nil && ip != "" {
				cache.Set(h, ip, isPrivate)
			}
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

	if ip, ok := resolveSystem(ctx, host); ok {
		return ip, isPrivateIPStr(ip)
	}

	if ip, ok := resolveOne(ctx, host, timeout); ok {
		return ip, isPrivateIPStr(ip)
	}
	select {
	case <-ctx.Done():
		return "", false
	case <-time.After(200 * time.Millisecond):
	}
	if ip, ok := resolveOne(ctx, host, timeout); ok {
		return ip, isPrivateIPStr(ip)
	}
	return "", false
}

func resolveSystem(ctx context.Context, host string) (string, bool) {
	sysCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(sysCtx, host)
	if err != nil {
		return "", false
	}
	for _, ip := range ips {
		if v4 := ip.IP.To4(); v4 != nil {
			return v4.String(), true
		}
	}
	return "", false
}

func resolveOne(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	resolveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	servers := []struct {
		addr string
		net  string
	}{
		{"100.100.100.100:53", "udp"}, // Tailscale DNS
		{"8.8.8.8:53", "tcp"},          // Google DNS over TCP (UDP often blocked)
		{"1.1.1.1:53", "tcp"},           // Cloudflare DNS over TCP
	}

	for _, s := range servers {
		c := new(dns.Client)
		c.Net = s.net
		c.Timeout = timeout
		r, _, err := c.ExchangeContext(resolveCtx, m, s.addr)
		if err != nil {
			continue
		}
		if len(r.Answer) == 0 {
			continue
		}
		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				return a.A.String(), false
			}
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

// ResolveStream resolves DNS for all hosts concurrently and streams results
// as they become available, rather than waiting for all to complete.
func ResolveStream(ctx context.Context, hosts []string, maxConcurrent int, timeout time.Duration, cache *DNSCache) <-chan DNSResult {
	out := make(chan DNSResult, maxConcurrent)

	go func() {
		defer close(out)
		var uncached []string
		for _, h := range hosts {
			if cache != nil {
				if ip, isPrivate, ok := cache.Get(h); ok {
					select {
					case out <- DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}:
					case <-ctx.Done():
						return
					}
					continue
				}
			}
			uncached = append(uncached, h)
		}

		if len(uncached) == 0 {
			return
		}

		g, ctx := errgroup.WithContext(ctx)
		g.SetLimit(maxConcurrent)

		for _, h := range uncached {
			h := h
			g.Go(func() error {
				ip, isPrivate := resolveWithRetry(ctx, h, timeout)
				if cache != nil && ip != "" {
					cache.Set(h, ip, isPrivate)
				}
				select {
				case out <- DNSResult{Host: h, IP: ip, IsPrivate: isPrivate}:
				case <-ctx.Done():
				}
				return nil
			})
		}
		g.Wait()
	}()

	return out
}