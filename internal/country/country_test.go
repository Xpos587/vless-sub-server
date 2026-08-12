package country

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseCodesNormalizesRepeatedValues(t *testing.T) {
	codes, err := ParseCodes([]string{"fi, ro", "FI,by"})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"FI", "RO", "BY"} {
		if _, ok := codes[code]; !ok {
			t.Fatalf("missing %s in %#v", code, codes)
		}
	}
	if len(codes) != 3 {
		t.Fatalf("codes = %#v", codes)
	}
}

func TestParseCodesRejectsInvalidCountry(t *testing.T) {
	for _, value := range []string{"F", "FIN", "12", "ZZ"} {
		if _, err := ParseCodes([]string{value}); err == nil {
			t.Fatalf("ParseCodes(%q) succeeded", value)
		}
	}
}

func TestObserveStabilizesCountryChanges(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	fi := Observation{IP: netip.MustParseAddr("203.0.113.1"), Country: "FI"}
	de := Observation{IP: netip.MustParseAddr("203.0.113.2"), Country: "DE"}

	result := Observe(FamilyResult{}, fi, now)
	if result.Status != Confirmed || result.Country != "FI" {
		t.Fatalf("first observation = %#v", result)
	}

	result = Observe(result, de, now.Add(time.Minute))
	if result.Status != Conflict || result.Country != "FI" || result.CandidateCountry != "DE" || result.CandidateCount != 1 {
		t.Fatalf("first change = %#v", result)
	}

	result = Observe(result, de, now.Add(2*time.Minute))
	if result.Status != Confirmed || result.Country != "DE" || result.CandidateCountry != "" {
		t.Fatalf("confirmed change = %#v", result)
	}
}

func TestObserveFailureRetainsLastConfirmedCountry(t *testing.T) {
	previous := FamilyResult{Available: true, Country: "FI", Status: Confirmed}
	if got := Observe(previous, Observation{}, time.Now()); got.Country != "FI" || got.Status != Confirmed {
		t.Fatalf("failed observation changed state: %#v", got)
	}
}

func TestFilterSelectsExactRouteCountry(t *testing.T) {
	route := RouteCountries{
		DirectV4: FamilyResult{Available: true, Country: "AE", Status: Confirmed},
		WarpV4:   FamilyResult{Available: true, Country: "FI", Status: Confirmed},
	}
	excluded := map[string]struct{}{"FI": {}}
	if got := Filter(route, false, excluded); !got.Include {
		t.Fatalf("direct route was filtered: %#v", got)
	}
	if got := Filter(route, true, excluded); got.Include || !got.Filtered {
		t.Fatalf("WARP route was not filtered: %#v", got)
	}
}

func TestFilterFailsClosedForUnknownOrConflict(t *testing.T) {
	excluded := map[string]struct{}{"RU": {}}
	if got := Filter(RouteCountries{}, false, excluded); got.Include || got.Unknown != 1 {
		t.Fatalf("unknown route decision = %#v", got)
	}
	route := RouteCountries{DirectV4: FamilyResult{Available: true, Country: "FI", Status: Conflict, CandidateCountry: "DE"}}
	if got := Filter(route, false, excluded); got.Include || got.Conflict != 1 {
		t.Fatalf("conflicted route decision = %#v", got)
	}
}

func TestFilterIgnoresUnavailableIPv6(t *testing.T) {
	route := RouteCountries{DirectV4: FamilyResult{Available: true, Country: "DE", Status: Confirmed}}
	if got := Filter(route, false, map[string]struct{}{"RU": {}}); !got.Include || got.Unknown != 0 {
		t.Fatalf("unavailable IPv6 affected decision: %#v", got)
	}
}

func TestFilterUsesEitherAvailableFamily(t *testing.T) {
	route := RouteCountries{
		DirectV4: FamilyResult{Available: true, Country: "DE", Status: Confirmed},
		DirectV6: FamilyResult{Available: true, Country: "RO", Status: Confirmed},
	}
	if got := Filter(route, false, map[string]struct{}{"RO": {}}); got.Include || !got.Filtered {
		t.Fatalf("excluded IPv6 country did not filter route: %#v", got)
	}
}

func TestFilterAppliesNewExcludedCandidateImmediately(t *testing.T) {
	route := RouteCountries{DirectV4: FamilyResult{
		Available: true, Country: "DE", Status: Conflict,
		CandidateCountry: "RU", ObservedCountry: "RU",
	}}
	got := Filter(route, false, map[string]struct{}{"RU": {}})
	if got.Include || !got.Filtered || got.Conflict != 1 {
		t.Fatalf("excluded candidate decision = %#v", got)
	}
}
