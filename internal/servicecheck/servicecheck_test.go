package servicecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func TestResultReasonNormalizesUnknownFailures(t *testing.T) {
	tests := []struct {
		result Result
		want   string
	}{
		{Result{Status: Available}, ""},
		{Result{Status: Unknown, Reason: "timeout", Detail: "request failed"}, "timeout"},
		{Result{Status: Unknown, Detail: "Cloudflare challenge"}, "challenge"},
		{Result{Status: Unknown, Detail: "unexpected HTTP status"}, "unexpected_status"},
		{Result{Status: Unknown, Detail: "region not found in page"}, "parse_error"},
		{Result{Status: Unknown, Detail: "request failed"}, "transport"},
	}
	for _, test := range tests {
		if got := ResultReason(test.result); got != test.want {
			t.Fatalf("ResultReason(%#v) = %q, want %q", test.result, got, test.want)
		}
	}
}

func TestFetchClassifiesClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	result := fetch(context.Background(), &http.Client{Timeout: 5 * time.Millisecond}, server.URL, nil)
	if result.ok || result.reason != "timeout" {
		t.Fatalf("fetch result = %#v", result)
	}
}
