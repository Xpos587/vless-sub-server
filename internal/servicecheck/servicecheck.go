package servicecheck

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Status is the coarse availability verdict for a service.
type Status string

const (
	Available  Status = "available"
	Restricted Status = "restricted"
	Blocked    Status = "blocked"
	Unknown    Status = "unknown"
)

// Result is one service availability probe outcome.
type Result struct {
	Service string
	Status  Status
	Region  string
	Reason  string
	Detail  string
}

func ResultReason(result Result) string {
	if result.Status != Unknown {
		return ""
	}
	if result.Reason != "" {
		return result.Reason
	}
	detail := strings.ToLower(result.Detail)
	switch {
	case strings.Contains(detail, "challenge"):
		return "challenge"
	case strings.Contains(detail, "unexpected http"), strings.Contains(detail, "unexpected response"), strings.Contains(detail, "unexpected destination"):
		return "unexpected_status"
	case strings.Contains(detail, "not found"), strings.Contains(detail, "wording present"):
		return "parse_error"
	case strings.Contains(detail, "request failed"):
		return "transport"
	default:
		return "unknown"
	}
}

// Checker probes one service through a given HTTP client (routed through a
// proxy or WARP chain by the caller).
type Checker interface {
	Name() string
	Check(ctx context.Context, client *http.Client) Result
}

const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"

// DefaultCheckers returns the service probes in display order.
func DefaultCheckers() []Checker {
	out := []Checker{
		chatGPTWeb{},
		chatGPTApp{},
		gemini{},
		youTubePremium{},
		netflix{},
		tiktok{},
		claude{},
		notebookLM{},
		reddit{},
		amazonPrime{},
	}
	out = append(out, AICheckers()...)
	out = append(out, MoreCheckers()...)
	return out
}

// CheckAll runs all checkers sequentially through client.
func CheckAll(ctx context.Context, client *http.Client, checkers []Checker) []Result {
	results := make([]Result, 0, len(checkers))
	for _, checker := range checkers {
		results = append(results, checker.Check(ctx, client))
	}
	return results
}

type fetchResult struct {
	status   int
	body     string
	finalURL string
	reason   string
	ok       bool
}

func fetch(ctx context.Context, client *http.Client, url string, headers map[string]string) fetchResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetchResult{reason: "parse_error"}
	}
	req.Header.Set("User-Agent", browserUA)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		reason := "transport"
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
			reason = "timeout"
		}
		return fetchResult{reason: reason}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fetchResult{status: resp.StatusCode, reason: "parse_error", ok: false}
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return fetchResult{status: resp.StatusCode, body: string(body), finalURL: finalURL, ok: true}
}

func requestFailure(service string, result fetchResult) Result {
	reason := result.reason
	if reason == "" {
		reason = "transport"
	}
	return Result{Service: service, Status: Unknown, Reason: reason, Detail: "request failed"}
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

var challengeMarkers = []string{
	"cf_chl_opt",
	"_cf_chl",
	"just a moment",
	"cf-browser-verification",
	"enable javascript and cookies to continue",
}

func isChallenge(status int, body string) bool {
	if status != 403 && status != 429 && status != 503 {
		return false
	}
	lower := strings.ToLower(body)
	for _, marker := range challengeMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

type chatGPTWeb struct{}

func (chatGPTWeb) Name() string { return "chatgpt_web" }

func (chatGPTWeb) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://api.openai.com/compliance/cookie_requirements", nil)
	if !r.ok {
		return requestFailure("chatgpt_web", r)
	}
	if containsFold(r.body, "unsupported_country") {
		return Result{Service: "chatgpt_web", Status: Blocked, Detail: "unsupported country"}
	}
	return Result{Service: "chatgpt_web", Status: Available}
}

type chatGPTApp struct{}

func (chatGPTApp) Name() string { return "chatgpt_app" }

func (chatGPTApp) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://ios.chat.openai.com", nil)
	if !r.ok {
		return requestFailure("chatgpt_app", r)
	}
	if isChallenge(r.status, r.body) {
		return Result{Service: "chatgpt_app", Status: Unknown, Detail: "Cloudflare challenge"}
	}
	switch {
	case containsFold(r.body, "disallowed isp"):
		return Result{Service: "chatgpt_app", Status: Blocked, Detail: "disallowed ISP"}
	case containsFold(r.body, "been blocked"):
		return Result{Service: "chatgpt_app", Status: Blocked, Detail: "blocked"}
	}
	return Result{Service: "chatgpt_app", Status: Available}
}

var reGeminiRegion = regexp.MustCompile(`,\d+,\d+,200,"([A-Z]{3})"`)

var geminiUnsupported = map[string]bool{
	"RUS": true, "BLR": true, "CHN": true, "PRK": true, "IRN": true, "CUB": true, "SYR": true,
}

type gemini struct{}

func (gemini) Name() string { return "gemini" }

func (gemini) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://gemini.google.com/app", map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !r.ok {
		return requestFailure("gemini", r)
	}
	if isChallenge(r.status, r.body) {
		return Result{Service: "gemini", Status: Unknown, Detail: "Cloudflare challenge"}
	}
	if r.status < 200 || r.status >= 400 {
		return Result{Service: "gemini", Status: Unknown, Detail: "unexpected HTTP status"}
	}
	m := reGeminiRegion.FindStringSubmatch(r.body)
	if m == nil {
		return Result{Service: "gemini", Status: Unknown, Detail: "region not found in page"}
	}
	region := m[1]
	if geminiUnsupported[region] {
		return Result{Service: "gemini", Status: Blocked, Region: region, Detail: "not offered in this country"}
	}
	return Result{Service: "gemini", Status: Available, Region: region}
}

type youTubePremium struct{}

func (youTubePremium) Name() string { return "youtube_premium" }

func (youTubePremium) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.youtube.com/premium", map[string]string{
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !r.ok {
		return requestFailure("youtube_premium", r)
	}
	body := strings.ToLower(r.body)
	switch {
	case strings.Contains(body, "youtube premium is not available in your country"):
		return Result{Service: "youtube_premium", Status: Blocked, Detail: "not offered in this country"}
	case strings.Contains(body, "ad-free"):
		return Result{Service: "youtube_premium", Status: Available}
	}
	return Result{Service: "youtube_premium", Status: Unknown, Detail: "neither offer nor refusal wording present"}
}

const (
	netflixLicensedTitle = "70143836"
	netflixOriginalTitle = "80197526"
)

type netflix struct{}

func (netflix) Name() string { return "netflix" }

func (netflix) Check(ctx context.Context, client *http.Client) Result {
	region, ok := netflixTitle(ctx, client, netflixLicensedTitle)
	if ok {
		return Result{Service: "netflix", Status: Available, Region: region, Detail: "full catalogue"}
	}
	region, ok = netflixTitle(ctx, client, netflixOriginalTitle)
	if ok {
		return Result{Service: "netflix", Status: Restricted, Region: region, Detail: "originals only"}
	}
	return Result{Service: "netflix", Status: Blocked, Detail: "not available"}
}

func netflixTitle(ctx context.Context, client *http.Client, id string) (string, bool) {
	r := fetch(ctx, client, "https://www.netflix.com/title/"+id, nil)
	if !r.ok || r.status == 404 || r.status < 200 || r.status >= 400 {
		return "", false
	}
	if r.finalURL == "" {
		return "", false
	}
	segments := strings.SplitN(strings.TrimPrefix(r.finalURL, "https://www.netflix.com/"), "/", 2)
	if len(segments) == 0 || segments[0] == "" {
		return "", false
	}
	if segments[0] == "title" {
		return "US", true
	}
	locale, _, _ := strings.Cut(segments[0], "-")
	if len(locale) != 2 {
		return "", false
	}
	return strings.ToUpper(locale), true
}

var tiktokBlockMarkers = []string{
	"service is currently unavailable in your region",
	"tiktok is not available in your country",
	"tiktok is unavailable in your country",
	"not available in your region",
}

type tiktok struct{}

func (tiktok) Name() string { return "tiktok" }

func (tiktok) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.tiktok.com/", map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !r.ok {
		return requestFailure("tiktok", r)
	}
	body := strings.ToLower(r.body)
	for _, marker := range tiktokBlockMarkers {
		if strings.Contains(body, marker) {
			return Result{Service: "tiktok", Status: Blocked, Detail: "blocked by region"}
		}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "tiktok", Status: Available}
	}
	return Result{Service: "tiktok", Status: Unknown, Detail: "unexpected HTTP status"}
}

var claudeUnavailableMarkers = []string{
	"app unavailable in region",
	"/app-unavailable-in-region",
	"unfortunately, claude isn't available here.",
	"unfortunately, claude isn't available here.",
	"unfortunately, claude isn't available here.",
}

type claude struct{}

func (claude) Name() string { return "claude" }

func (claude) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://claude.ai/", map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	})
	if !r.ok {
		return requestFailure("claude", r)
	}
	lower := strings.ToLower(r.body)
	if isChallenge(r.status, lower) {
		return Result{Service: "claude", Status: Unknown, Detail: "Cloudflare challenge"}
	}
	for _, marker := range claudeUnavailableMarkers {
		if strings.Contains(lower, marker) {
			return Result{Service: "claude", Status: Blocked, Detail: "not available in this region"}
		}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "claude", Status: Available}
	}
	return Result{Service: "claude", Status: Unknown, Detail: "unexpected HTTP status"}
}

type notebookLM struct{}

func (notebookLM) Name() string { return "notebooklm" }

func (notebookLM) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://notebooklm.google.com/", map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !r.ok {
		return requestFailure("notebooklm", r)
	}
	if isChallenge(r.status, r.body) {
		return Result{Service: "notebooklm", Status: Unknown, Detail: "Cloudflare challenge"}
	}
	if strings.Contains(r.finalURL, "location=unsupported") {
		return Result{Service: "notebooklm", Status: Blocked, Detail: "not offered in this country"}
	}
	if strings.Contains(r.finalURL, "accounts.google.com") || strings.Contains(r.finalURL, "/login") {
		return Result{Service: "notebooklm", Status: Available, Detail: "sign-in required"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "notebooklm", Status: Unknown, Detail: "unexpected destination"}
	}
	return Result{Service: "notebooklm", Status: Unknown, Detail: "unexpected HTTP status"}
}

type reddit struct{}

func (reddit) Name() string { return "reddit" }

func (reddit) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.reddit.com/svc/shreddit/reddit-chat", map[string]string{
		"Accept": "text/html,*/*;q=0.8",
	})
	if !r.ok {
		return requestFailure("reddit", r)
	}
	switch {
	case r.status == 200:
		return Result{Service: "reddit", Status: Available, Region: extractRedditRegion(r.body)}
	case r.status == 403:
		return Result{Service: "reddit", Status: Blocked, Detail: "forbidden"}
	}
	return Result{Service: "reddit", Status: Unknown, Detail: "unexpected HTTP status"}
}

var reRedditCountry = regexp.MustCompile(`country="([A-Z]{2})"`)

func extractRedditRegion(body string) string {
	if m := reRedditCountry.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

type amazonPrime struct{}

func (amazonPrime) Name() string { return "amazon_prime" }

func (amazonPrime) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.primevideo.com/", map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	})
	if !r.ok {
		return requestFailure("amazon_prime", r)
	}
	if m := regexp.MustCompile(`"currentTerritory":"([A-Z]{2})"`).FindStringSubmatch(r.body); m != nil {
		return Result{Service: "amazon_prime", Status: Available, Region: m[1]}
	}
	return Result{Service: "amazon_prime", Status: Blocked, Detail: "territory not found"}
}
