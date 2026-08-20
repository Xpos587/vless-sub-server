package servicecheck

import "testing"

func TestDefaultCheckersOrder(t *testing.T) {
	checkers := DefaultCheckers()
	if len(checkers) == 0 {
		t.Fatal("no checkers")
	}
	if checkers[0].Name() != "chatgpt_web" {
		t.Fatalf("first checker = %s, want chatgpt_web", checkers[0].Name())
	}
}

func TestIsChallenge(t *testing.T) {
	if !isChallenge(403, "<title>Just a moment...</title>") {
		t.Fatal("403 with Cloudflare marker should be challenge")
	}
	if isChallenge(200, "ok") {
		t.Fatal("200 should not be challenge")
	}
	if isChallenge(403, "unsupported_country") {
		t.Fatal("403 without markers should not be challenge")
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold("Unsupported_Country", "unsupported_country") {
		t.Fatal("case-insensitive contains failed")
	}
}

func TestExtractRedditRegion(t *testing.T) {
	if region := extractRedditRegion(`html country="DE" end`); region != "DE" {
		t.Fatalf("region = %s, want DE", region)
	}
	if region := extractRedditRegion("no country"); region != "" {
		t.Fatalf("region = %s, want empty", region)
	}
}
