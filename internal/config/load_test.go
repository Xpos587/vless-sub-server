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

func TestLoadRejectsBandwidthBudgetAboveHardLimit(t *testing.T) {
	t.Setenv("SUBSCRIPTION_URLS", "https://example.test/sub")
	t.Setenv("HWID", "test")
	t.Setenv("BANDWIDTH_BUDGET_BYTES", "33554433")
	if _, err := Load(); err == nil {
		t.Fatal("Load() error = nil, want hard bandwidth budget rejection")
	}
}
