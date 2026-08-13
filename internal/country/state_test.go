package country

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStateStorePersistsCountryEvidenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "countries.json")
	store, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := RouteCountries{WarpV4: FamilyResult{
		Available:   true,
		Country:     "FI",
		Status:      Confirmed,
		ConfirmedAt: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}}
	store.Set("credential-sensitive-hash", want)
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("credential-sensitive-hash")
	if !ok || got.WarpV4.Country != "FI" || got.WarpV4.Status != Confirmed {
		t.Fatalf("reopened state = %#v, %t", got, ok)
	}
}

func TestStateStoreTreatsEmptyPathAsDisabled(t *testing.T) {
	store, err := OpenStateStore("")
	if err != nil {
		t.Fatal(err)
	}
	store.Set("key", RouteCountries{DirectV4: FamilyResult{Country: "DE", Status: Confirmed}})
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("key"); !ok {
		t.Fatal("in-memory state missing")
	}
}

func TestNeedsReprobePrioritizesMissingRouteEvidence(t *testing.T) {
	confirmed := RouteCountries{
		DirectV4: FamilyResult{Available: true, Country: "DE", Status: Confirmed},
		WarpV4:   FamilyResult{Available: true, Country: "FI", Status: Confirmed},
	}
	if NeedsReprobe(confirmed) {
		t.Fatal("fully confirmed route selected for reprobe")
	}
	if !NeedsReprobe(RouteCountries{DirectV4: confirmed.DirectV4}) {
		t.Fatal("missing WARP evidence not selected for reprobe")
	}
	if !NeedsReprobe(RouteCountries{DirectV4: FamilyResult{Available: true, Country: "DE", Status: Conflict}}) {
		t.Fatal("conflicting direct evidence not selected for reprobe")
	}
}

func TestNeedsWarpReprobeIgnoresMissingDirectEvidence(t *testing.T) {
	route := RouteCountries{WarpV4: FamilyResult{Available: true, Country: "FI", Status: Confirmed}}
	if NeedsWarpReprobe(route) {
		t.Fatal("confirmed WARP route selected because direct evidence is absent")
	}
	route.WarpV4 = FamilyResult{}
	if !NeedsWarpReprobe(route) {
		t.Fatal("missing WARP evidence not selected")
	}
}
