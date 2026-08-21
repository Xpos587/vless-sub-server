package servicecheck

import (
	"context"
	"net/http"
	"regexp"
	"strings"
)

// Google Search captcha
type googleCaptcha struct{}

func (googleCaptcha) Name() string { return "google_captcha" }

var reGoogleBlocked = regexp.MustCompile(`(?i)unusual traffic from|is blocked|unaddressed abuse`)

func (googleCaptcha) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.google.com/search?q=cats", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("google_captcha", r)
	}
	if r.status == 429 || reGoogleBlocked.MatchString(r.body) {
		return Result{Service: "google_captcha", Status: Blocked, Detail: "IP flagged for abuse"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "google_captcha", Status: Available}
	}
	return Result{Service: "google_captcha", Status: Unknown, Detail: "unexpected HTTP status"}
}

// YouTube Music
type youTubeMusic struct{}

func (youTubeMusic) Name() string { return "youtube_music" }

func (youTubeMusic) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://music.youtube.com/", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("youtube_music", r)
	}
	body := strings.ToLower(r.body)
	if strings.Contains(body, "not available in your country") {
		return Result{Service: "youtube_music", Status: Blocked, Detail: "not offered in this country"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "youtube_music", Status: Available}
	}
	return Result{Service: "youtube_music", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Twitch
type twitch struct{}

func (twitch) Name() string { return "twitch" }

func (twitch) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.twitch.tv/", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("twitch", r)
	}
	if r.status == 403 {
		return Result{Service: "twitch", Status: Blocked, Detail: "forbidden"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "twitch", Status: Available}
	}
	return Result{Service: "twitch", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Spotify
type spotify struct{}

func (spotify) Name() string { return "spotify" }

func (spotify) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.spotify.com/", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("spotify", r)
	}
	body := strings.ToLower(r.body)
	if strings.Contains(body, "currently not available in your country") {
		return Result{Service: "spotify", Status: Blocked, Detail: "not offered in this country"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "spotify", Status: Available}
	}
	return Result{Service: "spotify", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Deezer
type deezer struct{}

func (deezer) Name() string { return "deezer" }

var reDeezerCountry = regexp.MustCompile(`'country':\s*'([^']*)'`)

func (deezer) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.deezer.com/", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("deezer", r)
	}
	if m := reDeezerCountry.FindStringSubmatch(r.body); m != nil {
		return Result{Service: "deezer", Status: Available, Region: m[1]}
	}
	return Result{Service: "deezer", Status: Unknown, Detail: "country not found"}
}

// Reddit Guest
type redditGuest struct{}

func (redditGuest) Name() string { return "reddit_guest" }

func (redditGuest) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.reddit.com/", map[string]string{"Accept": "text/html,*/*;q=0.8"})
	if !r.ok {
		return requestFailure("reddit_guest", r)
	}
	if r.status == 403 {
		return Result{Service: "reddit_guest", Status: Blocked, Detail: "forbidden"}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "reddit_guest", Status: Available}
	}
	return Result{Service: "reddit_guest", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Apple
type apple struct{}

func (apple) Name() string { return "apple" }

func (apple) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.apple.com/shop/browse/home/", nil)
	if !r.ok {
		return requestFailure("apple", r)
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "apple", Status: Available}
	}
	return Result{Service: "apple", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Steam
type steam struct{}

func (steam) Name() string { return "steam" }

var reSteamCountry = regexp.MustCompile(`steamCountry=([^%;]*)`)

func (steam) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://store.steampowered.com/", nil)
	if !r.ok {
		return requestFailure("steam", r)
	}
	if m := reSteamCountry.FindStringSubmatch(r.body); m != nil {
		return Result{Service: "steam", Status: Available, Region: m[1]}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "steam", Status: Available}
	}
	return Result{Service: "steam", Status: Unknown, Detail: "unexpected HTTP status"}
}

// PlayStation
type playstation struct{}

func (playstation) Name() string { return "playstation" }

func (playstation) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.playstation.com/", nil)
	if !r.ok {
		return requestFailure("playstation", r)
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "playstation", Status: Available}
	}
	return Result{Service: "playstation", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Ookla Speedtest
type ookla struct{}

func (ookla) Name() string { return "ookla" }

func (ookla) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.speedtest.net/", nil)
	if !r.ok {
		return requestFailure("ookla", r)
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "ookla", Status: Available}
	}
	return Result{Service: "ookla", Status: Unknown, Detail: "unexpected HTTP status"}
}

// JetBrains
type jetbrains struct{}

func (jetbrains) Name() string { return "jetbrains" }

func (jetbrains) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.jetbrains.com/", nil)
	if !r.ok {
		return requestFailure("jetbrains", r)
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "jetbrains", Status: Available}
	}
	return Result{Service: "jetbrains", Status: Unknown, Detail: "unexpected HTTP status"}
}

// Bing
type bing struct{}

func (bing) Name() string { return "bing" }

var reBingRegion = regexp.MustCompile(`Region\s*:\s*"([^"]+)"`)

func (bing) Check(ctx context.Context, client *http.Client) Result {
	r := fetch(ctx, client, "https://www.bing.com/", map[string]string{"Accept-Language": "en-US,en;q=0.9"})
	if !r.ok {
		return requestFailure("bing", r)
	}
	if m := reBingRegion.FindStringSubmatch(r.body); m != nil {
		return Result{Service: "bing", Status: Available, Region: m[1]}
	}
	if r.status >= 200 && r.status < 400 {
		return Result{Service: "bing", Status: Available}
	}
	return Result{Service: "bing", Status: Unknown, Detail: "unexpected HTTP status"}
}

// MoreCheckers returns additional service probes beyond the core set.
func MoreCheckers() []Checker {
	return []Checker{
		googleCaptcha{},
		youTubeMusic{},
		twitch{},
		spotify{},
		deezer{},
		redditGuest{},
		apple{},
		steam{},
		playstation{},
		ookla{},
		jetbrains{},
		bing{},
	}
}
