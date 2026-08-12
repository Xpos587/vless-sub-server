package quality

import (
	"sort"
	"time"
)

type BandwidthConfig struct {
	BytesPerProbe, BudgetBytes int64
	RefreshAfter, RetryAfter   time.Duration
}

func DefaultBandwidthConfig() BandwidthConfig {
	return BandwidthConfig{BytesPerProbe: 1 << 20, BudgetBytes: 32 << 20, RefreshAfter: 2 * time.Hour, RetryAfter: 30 * time.Minute}
}
func SelectBandwidthCandidates(entries []Runtime, now time.Time, cfg BandwidthConfig) []Runtime {
	eligible := make([]Runtime, 0, len(entries))
	for _, entry := range entries {
		if !entry.Reachable || entry.State == Dead || (!entry.LastBandwidthAttemptAt.IsZero() && now.Sub(entry.LastBandwidthAttemptAt) < cfg.RetryAfter) {
			continue
		}
		if !entry.LastBandwidthSuccessAt.IsZero() && now.Sub(entry.LastBandwidthSuccessAt) < cfg.RefreshAfter {
			continue
		}
		eligible = append(eligible, entry)
	}
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if a.LastBandwidthSuccessAt.IsZero() != b.LastBandwidthSuccessAt.IsZero() {
			return a.LastBandwidthSuccessAt.IsZero()
		}
		if !a.LastBandwidthSuccessAt.Equal(b.LastBandwidthSuccessAt) {
			return a.LastBandwidthSuccessAt.Before(b.LastBandwidthSuccessAt)
		}
		return a.Key < b.Key
	})
	max := int(cfg.BudgetBytes / cfg.BytesPerProbe)
	if len(eligible) > max {
		eligible = eligible[:max]
	}
	return eligible
}
