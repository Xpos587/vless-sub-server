package subview

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/country"
	"github.com/michael/vless-sub-server/internal/format"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/pipeline"
	"github.com/michael/vless-sub-server/internal/rename"
)

func TestParseDefaultsPreserveExistingFormats(t *testing.T) {
	urlOptions, err := Parse(url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if urlOptions.Format != FormatURL || urlOptions.Warp {
		t.Fatalf("URL defaults = %#v", urlOptions)
	}

	jsonOptions, err := Parse(url.Values{"format": {"json"}})
	if err != nil {
		t.Fatal(err)
	}
	if jsonOptions.Format != FormatJSON || !jsonOptions.Warp {
		t.Fatalf("JSON defaults = %#v", jsonOptions)
	}
}

func TestParseForClientKeepsRootURLDirectForEveryClient(t *testing.T) {
	for _, client := range []Client{ClientUnknown, ClientV2rayNG, ClientINCY, ClientExclave, ClientHusi} {
		options, err := ParseForClient(url.Values{}, client)
		if err != nil {
			t.Fatal(err)
		}
		if options.Format != FormatURL || options.Warp {
			t.Fatalf("%s options = %#v", client, options)
		}
	}
}

func TestParseForClientDisablesWarpForFlatteningClients(t *testing.T) {
	for _, client := range []Client{ClientExclave, ClientHusi} {
		options, err := ParseForClient(url.Values{"format": {"json"}}, client)
		if err != nil {
			t.Fatal(err)
		}
		if options.Format != FormatJSON || options.Warp {
			t.Fatalf("%s options = %#v", client, options)
		}
	}
}

func TestParseForClientRejectsExplicitWarpForFlatteningClients(t *testing.T) {
	for _, client := range []Client{ClientExclave, ClientHusi} {
		_, err := ParseForClient(url.Values{"format": {"json"}, "warp": {"on"}}, client)
		if err == nil {
			t.Fatalf("%s accepted an unsupported WARP chain", client)
		}
	}
}

func TestDetectClientUsesStableAndroidUserAgents(t *testing.T) {
	for name, test := range map[string]struct {
		userAgent string
		xClient   string
		want      Client
	}{
		"v2rayNG": {userAgent: "v2rayNG/2.2.6", want: ClientV2rayNG},
		"INCY":    {userAgent: "INCY/3.0/Android", xClient: "INCY", want: ClientINCY},
		"Exclave": {userAgent: "Exclave/0.17.46", want: ClientExclave},
		"Husi":    {userAgent: "husi/1.4.3 (143; sing-box 1.12.0)", want: ClientHusi},
		"unknown": {userAgent: "curl/8.17.0", want: ClientUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			if got := DetectClient(test.userAgent, test.xClient); got != test.want {
				t.Fatalf("DetectClient() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseRejectsWarpForURLFormat(t *testing.T) {
	_, err := Parse(url.Values{"warp": {"on"}})
	if err == nil {
		t.Fatal("warp=on with URL format succeeded")
	}
}

func TestParseProfileSelectsRussianRoutingBundle(t *testing.T) {
	options, err := Parse(url.Values{"format": {"json"}, "profile": {"ru"}})
	if err != nil {
		t.Fatal(err)
	}
	if options.Profile != format.RoutingProfileRussia {
		t.Fatalf("profile = %q, want %q", options.Profile, format.RoutingProfileRussia)
	}
}

func TestParseProfileRequiresJSON(t *testing.T) {
	_, err := Parse(url.Values{"profile": {"ru"}})
	if err == nil || err.Error() != "profile=ru requires format=json" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRejectsUnknownProfile(t *testing.T) {
	_, err := Parse(url.Values{"format": {"json"}, "profile": {"moon"}})
	if err == nil || err.Error() != "unsupported profile \"moon\"" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSingboxFormatDefaults(t *testing.T) {
	options, err := Parse(url.Values{"format": {"singbox"}})
	if err != nil {
		t.Fatal(err)
	}
	if options.Format != FormatSingbox || !options.Warp || options.Profile != format.RoutingProfileRussia {
		t.Fatalf("singbox defaults = %#v", options)
	}
}

func TestParseSingboxAllowsProfileNone(t *testing.T) {
	options, err := Parse(url.Values{"format": {"singbox"}, "profile": {"none"}})
	if err != nil {
		t.Fatal(err)
	}
	if options.Profile != format.RoutingProfileNone {
		t.Fatalf("profile = %q, want none", options.Profile)
	}
}

func TestParseSingboxKeepsWarpForFlatteningClients(t *testing.T) {
	for _, client := range []Client{ClientExclave, ClientHusi} {
		options, err := ParseForClient(url.Values{"format": {"singbox"}}, client)
		if err != nil {
			t.Fatal(err)
		}
		if !options.Warp {
			t.Fatalf("%s must keep warp for singbox (detour works): %#v", client, options)
		}
	}
}

func TestParseSingboxExplicitWarpOnForFlatteningClients(t *testing.T) {
	for _, client := range []Client{ClientExclave, ClientHusi} {
		options, err := ParseForClient(url.Values{"format": {"singbox"}, "warp": {"on"}}, client)
		if err != nil {
			t.Fatalf("%s rejected explicit warp=on for singbox: %v", client, err)
		}
		if !options.Warp {
			t.Fatalf("%s warp lost: %#v", client, options)
		}
	}
}

func TestParseSingboxWarpOff(t *testing.T) {
	options, err := Parse(url.Values{"format": {"singbox"}, "warp": {"off"}})
	if err != nil {
		t.Fatal(err)
	}
	if options.Warp {
		t.Fatalf("warp=off ignored: %#v", options)
	}
}

func TestRenderSingboxProducesSingleConfig(t *testing.T) {
	data := sampleCache()
	response := Render(data, Options{Format: FormatSingbox, Warp: true, Profile: format.RoutingProfileRussia})
	var config map[string]any
	if err := json.Unmarshal(response.Body, &config); err != nil {
		t.Fatalf("singbox body must be a single JSON object: %v", err)
	}
	for _, key := range []string{"outbounds", "route", "dns", "inbounds"} {
		if config[key] == nil {
			t.Fatalf("singbox config missing %s: %#v", key, config)
		}
	}
	if response.EntryCount == 0 {
		t.Fatalf("singbox response lost entries: %#v", response)
	}
}

func TestParseValidatesWarpAndFormat(t *testing.T) {
	for name, values := range map[string]url.Values{
		"warp":   {"warp": {"sometimes"}},
		"format": {"format": {"yaml"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(values); err == nil {
				t.Fatalf("Parse(%v) succeeded", values)
			}
		})
	}
}

func TestParseMergesExcludeParameters(t *testing.T) {
	options, err := Parse(url.Values{
		"format":  {"json"},
		"warp":    {"off"},
		"exclude": {"fi, ro", "FI,by"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Warp || len(options.Exclude) != 3 {
		t.Fatalf("options = %#v", options)
	}
}

func TestRenderFiltersExactDirectOrWarpCountryAndPreservesOrder(t *testing.T) {
	data := sampleCache()
	direct := Render(data, Options{Format: FormatJSON, Warp: false, Exclude: map[string]struct{}{"AE": {}}})
	warp := Render(data, Options{Format: FormatJSON, Warp: true, Exclude: map[string]struct{}{"FI": {}}})

	var directConfigs, warpConfigs []map[string]any
	if err := json.Unmarshal(direct.Body, &directConfigs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(warp.Body, &warpConfigs); err != nil {
		t.Fatal(err)
	}
	if len(directConfigs) != 1 || directConfigs[0]["remarks"] != "Second" {
		t.Fatalf("direct configs = %#v", directConfigs)
	}
	if len(warpConfigs) != 1 || warpConfigs[0]["remarks"] != "Second" {
		t.Fatalf("warp configs = %#v", warpConfigs)
	}
	if direct.Filtered != 1 || warp.Filtered != 1 {
		t.Fatalf("filtered direct=%d warp=%d", direct.Filtered, warp.Filtered)
	}
}

func TestRenderCountryFilteredViewFailsClosedButUnfilteredIncludesUnknown(t *testing.T) {
	data := sampleCache()
	data.Entries = append(data.Entries, pipeline.CachedEntry{Entry: renamed("Unknown", "unknown.example"), WarpHealthy: true})

	unfiltered := Render(data, Options{Format: FormatJSON, Warp: true})
	filtered := Render(data, Options{Format: FormatJSON, Warp: true, Exclude: map[string]struct{}{"RU": {}}})
	var allConfigs, filteredConfigs []map[string]any
	json.Unmarshal(unfiltered.Body, &allConfigs)
	json.Unmarshal(filtered.Body, &filteredConfigs)
	if len(allConfigs) != 3 || len(filteredConfigs) != 2 || filtered.Unknown != 1 {
		t.Fatalf("all=%d filtered=%d diagnostics=%#v", len(allConfigs), len(filteredConfigs), filtered)
	}
}

func TestRenderReturnsValidEmptyJSON(t *testing.T) {
	data := sampleCache()
	response := Render(data, Options{Format: FormatJSON, Warp: true, Exclude: map[string]struct{}{"FI": {}, "DE": {}}})
	if string(response.Body) != "[]" || response.Filtered != 2 {
		t.Fatalf("response = %#v body=%s", response, response.Body)
	}
}

func TestRenderWarpOffJSONContainsNoWireguard(t *testing.T) {
	response := Render(sampleCache(), Options{Format: FormatJSON, Warp: false})
	if string(response.Body) == "" || contains(string(response.Body), `"protocol": "wireguard"`) {
		t.Fatalf("direct response contains WARP: %s", response.Body)
	}
}

func TestRenderUsesPrecomputedURLButRegeneratesJSON(t *testing.T) {
	data := sampleCache()
	data.Output = "precomputed-url"
	data.JSONOutput = []byte(`[{"precomputed":true}]`)
	if got := Render(data, Options{Format: FormatURL, Warp: false}); string(got.Body) != data.Output {
		t.Fatalf("URL body = %q", got.Body)
	}
	got := Render(data, Options{Format: FormatJSON, Warp: true})
	if string(got.Body) == string(data.JSONOutput) || contains(string(got.Body), `"precomputed"`) {
		t.Fatalf("JSON body reused stale cache: %s", got.Body)
	}
	var configs []map[string]any
	if err := json.Unmarshal(got.Body, &configs); err != nil {
		t.Fatal(err)
	}
	if len(configs) == 0 || configs[0]["dns"] == nil {
		t.Fatalf("regenerated JSON has no DNS config: %#v", configs)
	}
}

func TestRenderExcludesWarpOnlyEntriesFromDirectSubscription(t *testing.T) {
	data := sampleCache()
	data.Entries[0].DirectHealthy = false
	data.Entries[0].WarpHealthy = true
	data.Entries[1].DirectHealthy = true
	data.Entries[1].WarpHealthy = false
	data.Output = ""
	data.JSONOutput = nil

	direct := Render(data, Options{Format: FormatURL, Warp: false})
	warp := Render(data, Options{Format: FormatJSON, Warp: true})
	if direct.EntryCount != 1 || !contains(string(direct.Body), "Second") || contains(string(direct.Body), "First") {
		t.Fatalf("direct response = %#v body=%s", direct, direct.Body)
	}
	var configs []map[string]any
	if err := json.Unmarshal(warp.Body, &configs); err != nil {
		t.Fatal(err)
	}
	if warp.EntryCount != 1 || len(configs) != 1 || configs[0]["remarks"] != "First" {
		t.Fatalf("WARP response = %#v configs=%#v", warp, configs)
	}
}

func TestRenderUsesFinalWarpNameForWarpJSONView(t *testing.T) {
	data := sampleCache()
	data.Entries[0].WarpEntry = renamed("🇻🇳 Hanoi (Cloudflare)", "first.example")

	response := Render(data, Options{Format: FormatJSON, Warp: true})
	var configs []map[string]any
	if err := json.Unmarshal(response.Body, &configs); err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[0]["remarks"] != "🇻🇳 Hanoi (Cloudflare)" {
		t.Fatalf("WARP config names = %#v", configs)
	}
}

func sampleCache() *pipeline.CachedData {
	return &pipeline.CachedData{
		Entries: []pipeline.CachedEntry{
			{
				Entry:         renamed("First", "first.example"),
				DirectHealthy: true,
				WarpHealthy:   true,
				Countries: country.RouteCountries{
					DirectV4: country.FamilyResult{Available: true, Country: "AE", Status: country.Confirmed},
					WarpV4:   country.FamilyResult{Available: true, Country: "FI", Status: country.Confirmed},
				},
			},
			{
				Entry:         renamed("Second", "second.example"),
				DirectHealthy: true,
				WarpHealthy:   true,
				Countries: country.RouteCountries{
					DirectV4: country.FamilyResult{Available: true, Country: "DE", Status: country.Confirmed},
					WarpV4:   country.FamilyResult{Available: true, Country: "DE", Status: country.Confirmed},
				},
			},
		},
		Metadata:    format.FormatMetadata{TotalAlive: 2},
		LastRefresh: time.Now(),
	}
}

func renamed(name, host string) rename.RenamedEntry {
	return rename.RenamedEntry{
		Record:          parse.ProxyRecord{Protocol: parse.VLESS, Host: host, Port: 443, UUIDOrPassword: name, QueryParams: map[string]string{"type": "tcp"}},
		RenamedFragment: name,
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
