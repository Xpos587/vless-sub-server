package ipintel

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type cymru struct {
	timeout  time.Duration
	resolver *net.Resolver
}

func newCymru(timeout time.Duration) *cymru {
	return &cymru{timeout: timeout, resolver: &net.Resolver{PreferGo: true}}
}

func (c *cymru) Name() string { return "cymru" }

func (c *cymru) Lookup(ctx context.Context, ip netip.Addr) (Result, bool) {
	if !ip.Is4() {
		return Result{}, false
	}
	reversed, ok := reverseIPv4Cymru(ip)
	if !ok {
		return Result{}, false
	}
	origin := reversed + ".origin.asn.cymru.com"
	txts, err := c.resolver.LookupTXT(ctx, origin)
	if err != nil || len(txts) == 0 {
		return Result{}, false
	}
	fields := splitCymru(txts[0])
	if len(fields) < 3 {
		return Result{}, false
	}
	result := Result{Source: c.Name(), CountryCode: strings.ToUpper(fields[2])}
	if first, _, _ := strings.Cut(fields[0], " "); first != "" {
		if n, err := strconv.Atoi(first); err == nil {
			result.ASN = "AS" + strconv.Itoa(n)
			result.Organization = c.asnName(ctx, n)
		}
	}
	return result, true
}

func (c *cymru) asnName(ctx context.Context, num int) string {
	queryCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	txts, err := c.resolver.LookupTXT(queryCtx, "AS"+strconv.Itoa(num)+".asn.cymru.com")
	if err != nil || len(txts) == 0 {
		return ""
	}
	fields := splitCymru(txts[0])
	if len(fields) >= 5 {
		name := strings.TrimSpace(fields[4])
		if i := strings.LastIndex(name, ","); i > 0 && len(name)-i <= 4 {
			name = strings.TrimSpace(name[:i])
		}
		return name
	}
	return ""
}

func reverseIPv4Cymru(ip netip.Addr) (string, bool) {
	parts := strings.Split(ip.Unmap().String(), ".")
	if len(parts) != 4 {
		return "", false
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0], true
}

func splitCymru(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
