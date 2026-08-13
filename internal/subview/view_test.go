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

func TestParseRejectsWarpForURLFormat(t *testing.T) {
	_, err := Parse(url.Values{"warp": {"on"}})
	if err == nil {
		t.Fatal("warp=on with URL format succeeded")
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

func TestRenderUsesPrecomputedDefaultBodies(t *testing.T) {
	data := sampleCache()
	data.Output = "precomputed-url"
	data.JSONOutput = []byte(`[{"precomputed":true}]`)
	if got := Render(data, Options{Format: FormatURL, Warp: false}); string(got.Body) != data.Output {
		t.Fatalf("URL body = %q", got.Body)
	}
	if got := Render(data, Options{Format: FormatJSON, Warp: true}); string(got.Body) != string(data.JSONOutput) {
		t.Fatalf("JSON body = %q", got.Body)
	}
}

func TestRenderKeepsWarpVerifiedEntriesInDirectSubscription(t *testing.T) {
	data := sampleCache()
	data.Entries[0].DirectHealthy = false
	data.Entries[0].WarpHealthy = true
	data.Entries[1].DirectHealthy = true
	data.Entries[1].WarpHealthy = false
	data.Output = ""
	data.JSONOutput = nil

	direct := Render(data, Options{Format: FormatURL, Warp: false})
	warp := Render(data, Options{Format: FormatJSON, Warp: true})
	if direct.EntryCount != 2 || !contains(string(direct.Body), "Second") || !contains(string(direct.Body), "First") {
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
