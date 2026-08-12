package pipeline

import (
	"testing"
	"time"

	"github.com/michael/vless-sub-server/internal/config"
	"github.com/michael/vless-sub-server/internal/dns"
	"github.com/michael/vless-sub-server/internal/exitprobe"
	"github.com/michael/vless-sub-server/internal/parse"
	"github.com/michael/vless-sub-server/internal/quality"
)

func TestCanPublishRejectsEmptyReplacementOfExistingCache(t *testing.T) {
	if CanPublish(0, true) {
		t.Fatal("empty refresh must not replace a populated cache")
	}
	if !CanPublish(1, true) {
		t.Fatal("non-empty refresh must be publishable")
	}
	if CanPublish(0, false) {
		t.Fatal("empty initial refresh must remain unavailable")
	}
}

func TestUpdateRuntimeRetainsFreshBandwidthMeasurement(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore(), cfg: &config.Config{BandwidthRefreshAfter: time.Hour}}
	key := "one"
	p.runtime.Set(quality.Runtime{Key: key, HasScore: true, ScoreEWMA: 30, LastBandwidthSuccessAt: time.Now(), Metrics: quality.Metrics{DownloadMbps: 50, BandwidthMeasured: true, BandwidthFresh: true}})
	p.updateRuntime(key, &exitprobe.ExitProbeResult{Metrics: quality.Metrics{InternetReachable: true, SampleCount: 5, SuccessCount: 5, RequestLatencyMS: 100}}, time.Now())
	runtime, _ := p.runtime.Get(key)
	if runtime.Metrics.DownloadMbps != 50 || !runtime.Metrics.BandwidthFresh {
		t.Fatalf("bandwidth was lost: %#v", runtime.Metrics)
	}
}

func TestStateRankOrdersRecoveringBeforeDegraded(t *testing.T) {
	if !(StateRank("HEALTHY") < StateRank("RECOVERING") && StateRank("RECOVERING") < StateRank("DEGRADED")) {
		t.Fatal("unexpected state ordering")
	}
}

func TestOutputEntriesExcludeDeadAndOrderByStateThenScore(t *testing.T) {
	p := &Pipeline{runtime: quality.NewStore()}
	records := []parse.ProxyRecord{
		{Protocol: parse.VLESS, Host: "healthy.example", Port: 443, UUIDOrPassword: "one"},
		{Protocol: parse.VLESS, Host: "recovering.example", Port: 443, UUIDOrPassword: "two"},
		{Protocol: parse.VLESS, Host: "degraded.example", Port: 443, UUIDOrPassword: "three"},
		{Protocol: parse.VLESS, Host: "dead.example", Port: 443, UUIDOrPassword: "four"},
	}
	for _, record := range records {
		state, score := quality.Healthy, 20.0
		switch record.Host {
		case "recovering.example":
			state, score = quality.Recovering, 1
		case "degraded.example":
			state, score = quality.Degraded, 1
		case "dead.example":
			state, score = quality.Dead, 0
		}
		p.runtime.Set(quality.Runtime{Key: identity(record), State: state, ScoreEWMA: score})
	}
	result := RefreshResult{}
	entries, _ := p.outputEntries(records, nil, map[string]*dns.DNSResult{
		"healthy.example": {}, "recovering.example": {}, "degraded.example": {}, "dead.example": {},
	}, &result)
	if len(entries) != 3 || entries[0].Record.Host != "healthy.example" || entries[1].Record.Host != "recovering.example" || entries[2].Record.Host != "degraded.example" {
		t.Fatalf("entries = %#v", entries)
	}
	if result.Dead != 1 {
		t.Fatalf("dead = %d, want 1", result.Dead)
	}
}
