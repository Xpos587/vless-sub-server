package quality

import (
	"sort"
	"time"
)

type Metrics struct {
	SampleCount       int
	SuccessCount      int
	GeoOK             bool
	InternetReachable bool
	RequestLatencyMS  float64
	MinLatencyMS      float64
	MaxLatencyMS      float64
	FailurePct        float64
	JitterMS          float64
	Blackhole         bool
	DownloadMbps      float64
	BandwidthMeasured bool
	BandwidthFresh    bool
}

func Aggregate(samples []time.Duration, failures, requested int, geoOK bool) Metrics {
	m := Metrics{SampleCount: requested, SuccessCount: len(samples), GeoOK: geoOK}
	if requested <= 0 {
		return m
	}
	m.FailurePct = float64(failures) / float64(requested) * 100
	m.InternetReachable = geoOK || len(samples) > 0
	m.Blackhole = !m.InternetReachable
	if len(samples) == 0 {
		return m
	}

	values := make([]float64, len(samples))
	for i, sample := range samples {
		values[i] = float64(sample) / float64(time.Millisecond)
	}
	m.MinLatencyMS, m.MaxLatencyMS = values[0], values[0]
	for _, value := range values {
		if value < m.MinLatencyMS {
			m.MinLatencyMS = value
		}
		if value > m.MaxLatencyMS {
			m.MaxLatencyMS = value
		}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	m.RequestLatencyMS = sorted[len(sorted)/2]
	if len(values) > 1 {
		for i := 1; i < len(values); i++ {
			delta := values[i] - values[i-1]
			if delta < 0 {
				delta = -delta
			}
			m.JitterMS += delta
		}
		m.JitterMS /= float64(len(values) - 1)
	}
	return m
}
