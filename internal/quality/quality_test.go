package quality

import (
	"math"
	"testing"
	"time"
)

func TestAggregateUsesMedianAndConsecutiveJitter(t *testing.T) {
	metrics := Aggregate(
		[]time.Duration{100 * time.Millisecond, 130 * time.Millisecond, 110 * time.Millisecond},
		2, 5, true,
	)

	if metrics.RequestLatencyMS != 110 {
		t.Fatalf("median latency = %v, want 110", metrics.RequestLatencyMS)
	}
	if metrics.FailurePct != 40 {
		t.Fatalf("failure percentage = %v, want 40", metrics.FailurePct)
	}
	if math.Abs(metrics.JitterMS-25) > 0.001 {
		t.Fatalf("jitter = %v, want 25", metrics.JitterMS)
	}
	if metrics.Blackhole || !metrics.InternetReachable {
		t.Fatalf("successful samples must be reachable and non-blackhole: %#v", metrics)
	}
}

func TestAggregateTreatsGeoOnlyAsPartialReachability(t *testing.T) {
	metrics := Aggregate(nil, 5, 5, true)
	if metrics.Blackhole || !metrics.InternetReachable || metrics.SuccessCount != 0 {
		t.Fatalf("geo-only result = %#v", metrics)
	}
}

func TestScoreBoundsBandwidthInfluenceAndColdStart(t *testing.T) {
	now := time.Now()
	cfg := DefaultScoringConfig()
	base := Metrics{InternetReachable: true, SuccessCount: 1, RequestLatencyMS: 200, FailurePct: 10, JitterMS: 20}
	fast := base
	fast.DownloadMbps = 100
	fast.BandwidthFresh = true

	baseScore, baseEWMA := Score(base, 0, false, now, cfg)
	fastScore, _ := Score(fast, 0, false, now, cfg)
	if baseScore < 0 || baseScore > 100 || baseEWMA != baseScore {
		t.Fatalf("cold score = %v, ewma = %v", baseScore, baseEWMA)
	}
	if fastScore >= baseScore || baseScore-fastScore > 10.001 {
		t.Fatalf("bandwidth influence invalid: base=%v fast=%v", baseScore, fastScore)
	}
}

func TestTransitionRecoversAfterCooldownAndTwoGoodObservations(t *testing.T) {
	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	cfg := DefaultStateConfig()
	r := RuntimeState{State: Healthy}
	r = Transition(r, Blackhole, now, cfg)
	r = Transition(r, Blackhole, now.Add(time.Minute), cfg)
	if r.State != Dead {
		t.Fatalf("state = %s, want DEAD", r.State)
	}
	r = Transition(r, Good, now.Add(cfg.DeadCooldown+time.Minute), cfg)
	if r.State != Recovering {
		t.Fatalf("state = %s, want RECOVERING", r.State)
	}
	r = Transition(r, Good, now.Add(cfg.DeadCooldown+2*time.Minute), cfg)
	if r.State != Healthy {
		t.Fatalf("state = %s, want HEALTHY", r.State)
	}
}

func TestSelectBandwidthCandidatesHonorsBudgetAndOldestFirst(t *testing.T) {
	now := time.Now()
	cfg := DefaultBandwidthConfig()
	cfg.BytesPerProbe = 10
	cfg.BudgetBytes = 20
	runtimes := []Runtime{
		{Key: "fresh", Reachable: true, LastBandwidthSuccessAt: now.Add(-time.Hour)},
		{Key: "old", Reachable: true, LastBandwidthSuccessAt: now.Add(-3 * time.Hour)},
		{Key: "never", Reachable: true},
		{Key: "dead", Reachable: true, State: Dead},
	}
	got := SelectBandwidthCandidates(runtimes, now, cfg)
	if len(got) != 2 || got[0].Key != "never" || got[1].Key != "old" {
		t.Fatalf("candidates = %#v", got)
	}
}

func TestStoreSnapshotDoesNotExposeMutableState(t *testing.T) {
	store := NewStore()
	store.Set(Runtime{Key: "one", Labels: map[string]string{"name": "original"}})
	snapshot := store.Snapshot()
	snapshot[0].Labels["name"] = "changed"
	if got := store.Snapshot()[0].Labels["name"]; got != "original" {
		t.Fatalf("store was mutated through snapshot: %q", got)
	}
}
