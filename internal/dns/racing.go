package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type racerResult struct {
	ip   string
	priv bool
}

func resolveRacing(ctx context.Context, host string, timeout time.Duration) (string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return host, isPrivateIP(ip)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	first := make(chan racerResult, 1)
	var wg sync.WaitGroup

	racers := []func(context.Context) (string, bool){
		func(ctx context.Context) (string, bool) { return resolveSystem(ctx, host) },
		func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "100.100.100.100:53", "udp") },
		func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "8.8.8.8:53", "tcp") },
		func(ctx context.Context) (string, bool) { return resolveMiekg(ctx, host, "1.1.1.1:53", "tcp") },
		func(ctx context.Context) (string, bool) { return resolveDoH(ctx, host, "https://cloudflare-dns.com/dns-query") },
		func(ctx context.Context) (string, bool) { return resolveDoH(ctx, host, "https://dns.google/dns-query") },
	}

	for _, r := range racers {
		wg.Add(1)
		go func(racer func(context.Context) (string, bool)) {
			defer wg.Done()
			if ip, ok := racer(ctx); ok && ip != "" {
				select {
				case first <- racerResult{ip: ip, priv: isPrivateIPStr(ip)}:
				default:
				}
			}
		}(r)
	}

	go func() { wg.Wait(); close(first) }()

	if r, ok := <-first; ok {
		return r.ip, r.priv
	}
	return "", false
}

func resolveMiekg(ctx context.Context, host, addr, network string) (string, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = network
	c.Timeout = 2 * time.Second
	r, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return "", false
	}
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String(), false
		}
	}
	return "", false
}

func resolveDoH(ctx context.Context, host, dohURL string) (string, bool) {
	u := fmt.Sprintf("%s?name=%s&type=A", dohURL, host)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	var dohResp struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return "", false
	}
	for _, a := range dohResp.Answer {
		if net.ParseIP(a.Data) != nil {
			return a.Data, false
		}
	}
	return "", false
}