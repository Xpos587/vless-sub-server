package pipeline

import (
	"net/netip"
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/dnsbl"
	"github.com/michael/vless-sub-server/internal/ipintel"
	"github.com/michael/vless-sub-server/internal/metrics"
	"github.com/michael/vless-sub-server/internal/portcheck"
	"github.com/michael/vless-sub-server/internal/servicecheck"
)

func TestServiceMetricsCountUniqueRouteTargetsAndExposeCacheState(t *testing.T) {
	directIP := netip.MustParseAddr("203.0.113.30")
	warpIP := netip.MustParseAddr("198.51.100.30")
	countries := country.RouteCountries{
		DirectV4: country.FamilyResult{Available: true, IP: directIP, Country: "US"},
		WarpV4:   country.FamilyResult{Available: true, IP: warpIP, Country: "DE"},
	}
	p := &Pipeline{serviceCache: servicecheck.NewCache(time.Hour)}
	p.cache.Store(&CachedData{Entries: []CachedEntry{
		{DirectHealthy: true, WarpHealthy: true, Countries: countries},
		{DirectHealthy: true, WarpHealthy: true, Countries: countries},
	}})
	p.serviceCache.Set(servicecheck.RouteKey{Route: "direct", IP: directIP.String()}, servicecheck.Result{Service: "gemini", Status: servicecheck.Unknown, Detail: "Cloudflare challenge"})
	p.serviceCache.Set(servicecheck.RouteKey{Route: "warp", IP: warpIP.String()}, servicecheck.Result{Service: "gemini", Status: servicecheck.Available})

	stats := p.buildServiceStats()
	assertServiceStat(t, stats, "direct", "gemini", "unknown", "challenge", "fresh", 1)
	assertServiceStat(t, stats, "warp", "gemini", "available", "", "fresh", 1)
}

func TestEnrichmentMetricsCountUniqueExitIPsByRoute(t *testing.T) {
	direct := country.FamilyResult{Available: true, IP: netip.MustParseAddr("203.0.113.10"), Country: "US"}
	warp := country.FamilyResult{Available: true, IP: netip.MustParseAddr("198.51.100.20"), Country: "DE"}
	entries := []CachedEntry{
		{
			DirectHealthy:    true,
			WarpHealthy:      true,
			Countries:        country.RouteCountries{DirectV4: direct, WarpV4: warp},
			Intel:            &ipintel.Intel{Type: ipintel.TypeHosting, RiskLevel: ipintel.RiskSuspicious, Flags: ipintel.Flags{Datacenter: true}},
			WarpIntel:        &ipintel.Intel{Type: ipintel.TypeResidential, RiskLevel: ipintel.RiskClean},
			PortResults:      []portcheck.PortResult{{Port: 80, Status: portcheck.Open}},
			WarpPortResults:  []portcheck.PortResult{{Port: 80, Status: portcheck.Closed}},
			DNSBLResults:     []dnsbl.Result{{Zone: "zen.spamhaus.org", Status: dnsbl.StatusListed}},
			WarpDNSBLResults: []dnsbl.Result{{Zone: "zen.spamhaus.org", Status: dnsbl.StatusClean}},
		},
		{
			DirectHealthy:    true,
			WarpHealthy:      true,
			Countries:        country.RouteCountries{DirectV4: direct, WarpV4: warp},
			Intel:            &ipintel.Intel{Type: ipintel.TypeHosting, RiskLevel: ipintel.RiskSuspicious, Flags: ipintel.Flags{Datacenter: true}},
			WarpIntel:        &ipintel.Intel{Type: ipintel.TypeResidential, RiskLevel: ipintel.RiskClean},
			PortResults:      []portcheck.PortResult{{Port: 80, Status: portcheck.Open}},
			WarpPortResults:  []portcheck.PortResult{{Port: 80, Status: portcheck.Closed}},
			DNSBLResults:     []dnsbl.Result{{Zone: "zen.spamhaus.org", Status: dnsbl.StatusListed}},
			WarpDNSBLResults: []dnsbl.Result{{Zone: "zen.spamhaus.org", Status: dnsbl.StatusClean}},
		},
	}

	exitStats := buildExitStats(entries)
	assertExitStat(t, exitStats, "direct", "ip_type", ipintel.TypeHosting, 1)
	assertExitStat(t, exitStats, "warp", "ip_type", ipintel.TypeResidential, 1)
	assertExitStat(t, exitStats, "direct", "reputation_flag", "datacenter", 1)

	ports := buildPortStats(entries)
	assertPortStat(t, ports, "direct", 80, string(portcheck.Open), 1)
	assertPortStat(t, ports, "warp", 80, string(portcheck.Closed), 1)

	lists := buildDNSBLStats(entries)
	assertDNSBLStat(t, lists, "direct", "zen.spamhaus.org", dnsbl.StatusListed, 1)
	assertDNSBLStat(t, lists, "warp", "zen.spamhaus.org", dnsbl.StatusClean, 1)
}

func assertExitStat(t *testing.T, stats []metrics.ExitStat, route, kind, value string, count int) {
	t.Helper()
	for _, stat := range stats {
		if stat.Route == route && stat.Kind == kind && stat.Value == value && stat.Count == count {
			return
		}
	}
	t.Fatalf("missing exit stat route=%s kind=%s value=%s count=%d in %#v", route, kind, value, count, stats)
}

func assertPortStat(t *testing.T, stats []metrics.PortStat, route string, port int, status string, count int) {
	t.Helper()
	for _, stat := range stats {
		if stat.Route == route && stat.Port == port && stat.Status == status && stat.Count == count {
			return
		}
	}
	t.Fatalf("missing port stat in %#v", stats)
}

func assertDNSBLStat(t *testing.T, stats []metrics.DNSBLStat, route, zone, status string, count int) {
	t.Helper()
	for _, stat := range stats {
		if stat.Route == route && stat.Zone == zone && stat.Status == status && stat.Count == count {
			return
		}
	}
	t.Fatalf("missing DNSBL stat in %#v", stats)
}

func assertServiceStat(t *testing.T, stats []metrics.ServiceStat, route, service, status, reason, cacheState string, count int) {
	t.Helper()
	for _, stat := range stats {
		if stat.Route == route && stat.Service == service && stat.Status == status && stat.Reason == reason && stat.CacheState == cacheState && stat.Count == count {
			return
		}
	}
	t.Fatalf("missing service stat in %#v", stats)
}
