package config

import "testing"

func TestLoadRejectsInvalidProbeSampleCount(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	t.Setenv("PROBE_SAMPLE_COUNT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want invalid sample count")
	}
}

func TestLoadReadsProbeSamplingValues(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	t.Setenv("PROBE_SAMPLE_COUNT", "3")
	t.Setenv("PROBE_SAMPLE_GAP", "25ms")
	t.Setenv("PROBE_SAMPLE_TIMEOUT", "2s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ProbeSampleCount != 3 || cfg.ProbeSampleGap.String() != "25ms" || cfg.ProbeSampleTimeout.String() != "2s" {
		t.Fatalf("cfg = %#v", cfg)
	}
}

func TestLoadUsesDirectExitObserverByDefault(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExitObserverURL != "https://exit-observer.hypcat.net/_exit" {
		t.Fatalf("ExitObserverURL = %q", cfg.ExitObserverURL)
	}
}

func TestLoadRejectsBandwidthBudgetAboveHardLimit(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	t.Setenv("BANDWIDTH_BUDGET_BYTES", "33554433")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want hard bandwidth budget rejection")
	}
}

func TestSourceAliasPrefersExplicitAndHashesOtherwise(t *testing.T) {
	cfg := &Config{SubscriptionURLs: []string{
		"https://volnalink.example/secret-token-1",
		"https://other.example/secret-token-2",
		"https://third.example/secret-token-3",
	}}
	cfg.SourceAliases = []string{"volnalink", "other"}

	if got := cfg.SourceAlias(0); got != "volnalink" {
		t.Fatalf("alias 0 = %q", got)
	}
	if got := cfg.SourceAlias(1); got != "other" {
		t.Fatalf("alias 1 = %q", got)
	}
	hashed := cfg.SourceAlias(2)
	if len(hashed) != 8 {
		t.Fatalf("hashed alias = %q, want 8 hex chars", hashed)
	}
	for _, forbidden := range []string{"third.example", "secret-token-3"} {
		if hashed == forbidden || hashed == cfg.SubscriptionURLs[2] {
			t.Fatalf("alias leaks source URL: %q", hashed)
		}
	}
}

func TestLoadMetricsPortDefault(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsPort != 9090 {
		t.Fatalf("MetricsPort = %d, want 9090", cfg.MetricsPort)
	}
}
