package quality

import (
	"math"
	"time"
)

type ScoringConfig struct{ EWMAAlpha float64 }

func DefaultScoringConfig() ScoringConfig { return ScoringConfig{EWMAAlpha: 0.35} }

func Score(m Metrics, previous float64, hasPrevious bool, _ time.Time, cfg ScoringConfig) (float64, float64) {
	if !m.InternetReachable {
		return previous, previous
	}
	if m.SuccessCount == 0 {
		return 95, ewma(previous, 95, hasPrevious, cfg.EWMAAlpha)
	}
	latency := clamp((m.RequestLatencyMS-100)/900, 0, 1)
	failure := clamp(m.FailurePct/100, 0, 1)
	jitter := clamp(m.JitterMS/300, 0, 1)
	bw := 0.5
	if m.BandwidthFresh {
		bw = 1 - clamp(math.Log1p(m.DownloadMbps)/math.Log1p(100), 0, 1)
	}
	raw := 100 * (0.35*latency + 0.40*failure + 0.15*jitter + 0.10*bw)
	return raw, ewma(previous, raw, hasPrevious, cfg.EWMAAlpha)
}

func ewma(previous, current float64, hasPrevious bool, alpha float64) float64 {
	if !hasPrevious {
		return current
	}
	return alpha*current + (1-alpha)*previous
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
