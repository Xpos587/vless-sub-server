package dnsbl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type List struct {
	Zone string
	Name string
}

type Result struct {
	Zone       string
	Name       string
	Listed     bool
	ReturnCode string
	Status     string
}

const (
	StatusListed  = "listed"
	StatusClean   = "clean"
	StatusUnknown = "unknown"
)

var DefaultLists = []List{
	{"zen.spamhaus.org", "Spamhaus ZEN"},
	{"b.barracudacentral.org", "Barracuda BRBL"},
	{"bl.spamcop.net", "SpamCop"},
	{"dnsbl.sorbs.net", "SORBS aggregate"},
	{"all.spamrats.com", "Spamrats"},
	{"bl.mailspike.net", "Mailspike"},
	{"bl.spameatingmonkey.net", "SpamEatingMonkey"},
	{"dnsbl-1.uceprotect.net", "UCEProtect-1"},
	{"ix.dnsbl.manitu.net", "Manitu"},
	{"spam.dnsbl.sophos.com", "Sophos"},
}

func CheckIP(ctx context.Context, ip netip.Addr, lists []List, timeout time.Duration, maxConcurrent int) []Result {
	results := make([]Result, len(lists))
	if !ip.Is4() || len(lists) == 0 {
		for i, list := range lists {
			results[i] = Result{Zone: list.Zone, Name: list.Name, Status: StatusUnknown}
		}
		return results
	}
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	reversed, ok := reverseIPv4(ip)
	if !ok {
		for i, list := range lists {
			results[i] = Result{Zone: list.Zone, Name: list.Name, Status: StatusUnknown}
		}
		return results
	}
	resolver := &net.Resolver{PreferGo: true}
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for i, list := range lists {
		wg.Add(1)
		go func(i int, list List) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{Zone: list.Zone, Name: list.Name, Status: StatusUnknown}
				return
			}
			defer func() { <-sem }()
			results[i] = lookup(ctx, resolver, reversed, list, timeout)
		}(i, list)
	}
	wg.Wait()
	return results
}

func lookup(ctx context.Context, resolver *net.Resolver, reversed string, list List, timeout time.Duration) Result {
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name := reversed + "." + list.Zone
	ips, err := resolver.LookupHost(queryCtx, name)
	status := classifyLookup(ips, err)
	if status == StatusClean {
		return Result{Zone: list.Zone, Name: list.Name, Status: StatusClean}
	}
	if status == StatusUnknown {
		return Result{Zone: list.Zone, Name: list.Name, Status: StatusUnknown}
	}
	code := ips[0]
	return Result{Zone: list.Zone, Name: list.Name, Listed: true, ReturnCode: code, Status: StatusListed}
}

func classifyLookup(ips []string, err error) string {
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return StatusClean
		}
		return StatusUnknown
	}
	if len(ips) == 0 {
		return StatusUnknown
	}
	if strings.HasPrefix(ips[0], "127.") {
		return StatusListed
	}
	return StatusUnknown
}

func reverseIPv4(ip netip.Addr) (string, bool) {
	parts := strings.Split(ip.String(), ".")
	if len(parts) != 4 {
		return "", false
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0], true
}
