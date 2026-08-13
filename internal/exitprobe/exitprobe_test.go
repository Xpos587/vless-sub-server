package exitprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/geo"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/quality"
	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestAggregateHealthSamplesKeepsGeoOnlyProxyReachable(t *testing.T) {
	metrics := aggregateHealthSamples(nil, 5, true)
	if !metrics.GeoOK || !metrics.InternetReachable || metrics.Blackhole {
		t.Fatalf("geo-only metrics = %#v", metrics)
	}
}

func TestAggregateHealthSamplesCalculatesMedian(t *testing.T) {
	metrics := aggregateHealthSamples(
		[]time.Duration{100 * time.Millisecond, 130 * time.Millisecond, 110 * time.Millisecond},
		5,
		true,
	)
	if metrics.RequestLatencyMS != 110 || metrics.FailurePct != 40 {
		t.Fatalf("metrics = %#v", metrics)
	}
}

func TestHealthProbeAcceptsSuccessfulNonEmptyDownloadResponse(t *testing.T) {
	if !healthResponseOK([]byte("ok"), true) {
		t.Fatal("successful health response with a body was rejected")
	}
	if healthResponseOK(nil, false) {
		t.Fatal("failed health response was accepted")
	}
}

func TestBuildOutboundSSProtocol(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.SS,
		Host:           "1.2.3.4",
		Port:           8388,
		UUIDOrPassword: "testpass",
		QueryParams:    map[string]string{"method": "aes-256-gcm"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	if ob.Protocol != "shadowsocks" {
		t.Fatalf("expected protocol 'shadowsocks', got %q", ob.Protocol)
	}
}

func TestBuildOutboundVMessSecurity(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.VMess,
		Host:           "1.2.3.4",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams:    map[string]string{"scy": "aes-128-gcm", "security": "tls", "type": "ws"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	data, _ := json.Marshal(ob)
	var parsed struct {
		Settings struct {
			Vnext []struct {
				Users []struct {
					Security string `json:"security"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	json.Unmarshal(data, &parsed)
	userSec := parsed.Settings.Vnext[0].Users[0].Security
	if userSec != "aes-128-gcm" {
		t.Fatalf("expected user security 'aes-128-gcm', got %q", userSec)
	}
}

func TestBuildStreamSettingsRealityNoFlowInSettings(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "reality", "sni": "example.com", "fp": "chrome", "pbk": "pubkey", "sid": "short", "flow": "xtls-rprx-vision", "spx": "/path"},
	}
	ss := buildStreamSettings(rec)
	rs := ss["realitySettings"].(map[string]any)
	if _, hasFlow := rs["flow"]; hasFlow {
		t.Fatal("flow should NOT be in realitySettings")
	}
	if _, hasSpiderX := rs["spiderX"]; !hasSpiderX {
		t.Fatal("spiderX should be in realitySettings")
	}
	if rs["spiderX"] != "/path" {
		t.Fatalf("expected spiderX=/path, got %v", rs["spiderX"])
	}
}

func TestBuildStreamSettingsTCPHeaderType(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "none", "type": "tcp", "headerType": "http"},
	}
	ss := buildStreamSettings(rec)
	tc, ok := ss["tcpSettings"].(map[string]any)
	if !ok {
		t.Fatal("expected tcpSettings for headerType=http")
	}
	header := tc["header"].(map[string]any)
	if header["type"] != "http" {
		t.Fatalf("expected header type http, got %v", header["type"])
	}
}

func TestBuildStreamSettingsTLSAlpn(t *testing.T) {
	rec := parse.ProxyRecord{
		Host:        "1.2.3.4",
		Port:        443,
		QueryParams: map[string]string{"security": "tls", "type": "tcp", "alpn": "h2,http/1.1"},
	}
	ss := buildStreamSettings(rec)
	ts := ss["tlsSettings"].(map[string]any)
	alpn := ts["alpn"]
	if alpn == nil {
		t.Fatal("expected alpn in tlsSettings")
	}
	alpnArr := alpn.([]string)
	if len(alpnArr) != 2 || alpnArr[0] != "h2" {
		t.Fatalf("expected alpn [h2, http/1.1], got %v", alpnArr)
	}
}

func TestBuildStreamSettingsXHTTPPreservesCompleteExtra(t *testing.T) {
	rec := parse.ProxyRecord{
		Host: "1.2.3.4", Port: 443,
		QueryParams: map[string]string{
			"type": "xhttp", "security": "reality", "path": "/explicit", "mode": "packet-up",
			"extra": `{"headers":{"User-Agent":"Mozilla/5.0"},"xmux":{"maxConcurrency":4},"noSSEHeader":true,"futureOption":{"enabled":true}}`,
		},
	}
	ss := buildStreamSettings(rec)
	xh, ok := ss["xhttpSettings"].(map[string]any)
	if !ok {
		t.Fatalf("xhttpSettings missing: %#v", ss)
	}
	if xh["path"] != "/explicit" || xh["mode"] != "packet-up" {
		t.Fatalf("explicit xHTTP fields lost: %#v", xh)
	}
	if _, ok := xh["extra"].(json.RawMessage); !ok {
		t.Fatalf("complete extra lost: %#v", xh)
	}
}

func TestBuildOutboundOnlyConfigAddsExactWarpChain(t *testing.T) {
	data := buildOutboundOnlyConfig([]parse.ProxyRecord{{
		Protocol: parse.VLESS, Host: "example.com", Port: 443, UUIDOrPassword: "uuid",
		QueryParams: map[string]string{"type": "xhttp", "path": "/x"},
	}})
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Outbounds) != 3 {
		t.Fatalf("outbounds = %d, want direct+proxy+warp", len(cfg.Outbounds))
	}
	proxy, warp := cfg.Outbounds[1], cfg.Outbounds[2]
	if proxy["tag"] != "proxy_0_out" || warp["tag"] != "warp_0_out" || warp["protocol"] != "wireguard" {
		t.Fatalf("unexpected chain: %#v", cfg.Outbounds)
	}
	sockopt := warp["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if sockopt["dialerProxy"] != "proxy_0_out" {
		t.Fatalf("WARP does not dial through proxy: %#v", sockopt)
	}
}

func TestParseCloudflareTraceUsesFinalIPAndLocNotColo(t *testing.T) {
	observation, ok := parseCloudflareTrace([]byte("fl=123\nip=2606:4700:1234::1\nloc=FI\ncolo=DXB\nwarp=on\n"))
	if !ok {
		t.Fatal("valid trace rejected")
	}
	if observation.IP != netip.MustParseAddr("2606:4700:1234::1") || observation.Country != "FI" {
		t.Fatalf("observation = %#v", observation)
	}
}

func TestParseCountryIsUsesObservedIPAndCountry(t *testing.T) {
	observation, ok := parseCountryIs([]byte(`{"ip":"198.51.100.4","country":"FI"}`))
	if !ok || observation.IP != netip.MustParseAddr("198.51.100.4") || observation.Country != "FI" {
		t.Fatalf("observation = %#v, ok=%t", observation, ok)
	}
}

func TestParseIPSBGeoKeepsCityAndISP(t *testing.T) {
	info, observation, ok := parseIPSBGeo([]byte(`{"ip":"198.51.100.4","country_code":"FI","city":"Helsinki","isp":"Example Transit","organization":"Example Org"}`))
	if !ok || observation.Country != "FI" || info == nil || info.City != "Helsinki" || info.ISP != "Example Transit" || info.IP != "198.51.100.4" {
		t.Fatalf("info=%#v observation=%#v ok=%t", info, observation, ok)
	}
}

func TestProbeCountryUsesCountryIsAfterOtherWitnessesFail(t *testing.T) {
	var targets []string
	request := func(_ context.Context, _, target string, _ time.Duration) ([]byte, bool) {
		targets = append(targets, target)
		if target == countryIsAPIURL {
			return []byte(`{"ip":"198.51.100.4","country":"FI"}`), true
		}
		return nil, false
	}
	observation, source := probeCountry(context.Background(), request, "warp_0_out", time.Second, traceWitness, ipWhoisWitness, countryIsWitness)
	if source != "country-is" || observation.Country != "FI" || len(targets) != 3 {
		t.Fatalf("observation=%#v source=%q targets=%#v", observation, source, targets)
	}
}

func TestParseCloudflareTraceRejectsInvalidCountryOrIP(t *testing.T) {
	for _, body := range []string{
		"ip=not-an-ip\nloc=FI\n",
		"ip=203.0.113.1\nloc=ZZ\n",
		"ip=203.0.113.1\ncolo=HEL\n",
	} {
		if _, ok := parseCloudflareTrace([]byte(body)); ok {
			t.Fatalf("invalid trace accepted: %q", body)
		}
	}
}

func TestObservationFromIPWhoisRequiresObservedIPAndCountry(t *testing.T) {
	observation, ok := observationFromIPWhois(geo.IPWhoisResponse{Success: true, IP: "203.0.113.1", CountryCode: "AE"})
	if !ok || observation.Country != "AE" || !observation.IP.Is4() {
		t.Fatalf("observation = %#v, ok=%t", observation, ok)
	}
	if _, ok := observationFromIPWhois(geo.IPWhoisResponse{Success: true, IP: "203.0.113.1", CountryCode: "ZZ"}); ok {
		t.Fatal("invalid country accepted")
	}
}

func TestXrayCoreAcceptsCompleteXHTTPExtra(t *testing.T) {
	data := buildOutboundOnlyConfig([]parse.ProxyRecord{{
		Protocol: parse.VLESS, Host: "example.com", Port: 443, UUIDOrPassword: "uuid",
		QueryParams: map[string]string{
			"type": "xhttp", "security": "reality", "sni": "example.com", "pbk": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "path": "/x", "mode": "packet-up",
			"extra": `{"headers":{"User-Agent":"Mozilla/5.0"},"xPaddingBytes":"100-1000","scMaxEachPostBytes":"500000-1000000","xmux":{"maxConcurrency":4,"hMaxRequestTimes":"600-900"},"noSSEHeader":true}`,
		},
	}})
	decoded, err := serial.DecodeJSONConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode complete xHTTP config: %v\n%s", err, data)
	}
	if _, err := decoded.Build(); err != nil {
		t.Fatalf("build complete xHTTP config: %v\n%s", err, data)
	}
}

func TestProbeCountryUsesTraceFirstAndStopsAfterSuccess(t *testing.T) {
	var targets []string
	request := func(_ context.Context, _, target string, _ time.Duration) ([]byte, bool) {
		targets = append(targets, target)
		return []byte("ip=198.51.100.1\nloc=FI\ncolo=DXB\n"), true
	}
	observation, source := probeCountry(context.Background(), request, "warp_0_out", time.Second, traceWitness, ipWhoisWitness)
	if observation.Country != "FI" || source != "cf-trace" || len(targets) != 1 || targets[0] != traceAPIURL {
		t.Fatalf("observation=%#v source=%q targets=%#v", observation, source, targets)
	}
}

func TestProbeCountryFallsBackToIPWhois(t *testing.T) {
	var targets []string
	request := func(_ context.Context, _, target string, _ time.Duration) ([]byte, bool) {
		targets = append(targets, target)
		if target == traceAPIURL {
			return []byte("colo=HEL\n"), true
		}
		return []byte(`{"success":true,"ip":"203.0.113.1","country_code":"DE"}`), true
	}
	observation, source := probeCountry(context.Background(), request, "warp_0_out", time.Second, traceWitness, ipWhoisWitness)
	if observation.Country != "DE" || source != "ipwho" || len(targets) != 2 || targets[1] != geoAPIURL {
		t.Fatalf("observation=%#v source=%q targets=%#v", observation, source, targets)
	}
}

func TestBuildOutboundOnlyConfigSuppressesExpectedWireguardWarnings(t *testing.T) {
	data := buildOutboundOnlyConfig(nil)
	var cfg struct {
		Log map[string]any `json:"log"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Log["loglevel"] != "error" {
		t.Fatalf("probe loglevel = %#v", cfg.Log)
	}
}

func TestBuildProbeResultPreservesWarpCountryForDirectBlackhole(t *testing.T) {
	warpObservation := country.Observation{IP: netip.MustParseAddr("198.51.100.1"), Country: "FI"}
	result := buildProbeResult(
		nil,
		country.Observation{}, "none",
		warpObservation, "cf-trace",
		quality.Metrics{Blackhole: true},
	)
	if result.WarpCountry != warpObservation || result.WarpSource != "cf-trace" {
		t.Fatalf("WARP evidence was lost: %#v", result)
	}
	if result.GeoInfo != nil {
		t.Fatalf("invalid direct geo was published: %#v", result.GeoInfo)
	}
}

func TestRetryMissingCountriesUsesWarmedRoutesOnlyForMissingEvidence(t *testing.T) {
	var tags []string
	request := func(_ context.Context, tag, _ string, _ time.Duration) ([]byte, bool) {
		tags = append(tags, tag)
		countryCode := "DE"
		ip := "203.0.113.1"
		if tag == "warp_0_out" {
			countryCode = "FI"
			ip = "198.51.100.1"
		}
		return []byte("ip=" + ip + "\nloc=" + countryCode + "\n"), true
	}
	direct, directSource, warp, warpSource := retryMissingCountries(
		context.Background(), request, "proxy_0_out", "warp_0_out", time.Second,
		country.Observation{}, "none", country.Observation{}, "none", true,
	)
	if direct.Country != "DE" || directSource != "cf-trace-retry" || warp.Country != "FI" || warpSource != "cf-trace-retry" {
		t.Fatalf("direct=%#v/%s warp=%#v/%s", direct, directSource, warp, warpSource)
	}
	if len(tags) != 2 {
		t.Fatalf("retry tags = %#v", tags)
	}

	tags = nil
	confirmed := country.Observation{IP: netip.MustParseAddr("192.0.2.1"), Country: "NL"}
	_, _, _, _ = retryMissingCountries(
		context.Background(), request, "proxy_0_out", "warp_0_out", time.Second,
		confirmed, "ipwho", confirmed, "cf-trace", true,
	)
	if len(tags) != 0 {
		t.Fatalf("confirmed countries were retried: %#v", tags)
	}
}

func TestRetryMissingCountriesSkipsUnreachableDirectRoute(t *testing.T) {
	called := false
	request := func(context.Context, string, string, time.Duration) ([]byte, bool) {
		called = true
		return nil, false
	}
	retryMissingCountries(context.Background(), request, "proxy_0_out", "warp_0_out", time.Second,
		country.Observation{}, "none", country.Observation{}, "none", false)
	if called {
		t.Fatal("unreachable route triggered post-health retry")
	}
}

func TestBuildOutboundVMessSecurityDefault(t *testing.T) {
	rec := parse.ProxyRecord{
		Protocol:       parse.VMess,
		Host:           "1.2.3.4",
		Port:           443,
		UUIDOrPassword: "uuid",
		QueryParams:    map[string]string{"security": "tls", "type": "ws"},
	}
	ob := buildOutbound(rec, "proxy_0_out")
	data, _ := json.Marshal(ob)
	var parsed struct {
		Settings struct {
			Vnext []struct {
				Users []struct {
					Security string `json:"security"`
				} `json:"users"`
			} `json:"vnext"`
		} `json:"settings"`
	}
	json.Unmarshal(data, &parsed)
	userSec := parsed.Settings.Vnext[0].Users[0].Security
	if userSec != "auto" {
		t.Fatalf("expected user security 'auto' (default), got %q", userSec)
	}
}
