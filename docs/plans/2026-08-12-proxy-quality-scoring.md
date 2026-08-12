# Proxy Quality Scoring Implementation Plan

> **For agentic workers:** This approved plan is executed inline in the current
> session by the user's explicit instruction. Steps use checkbox (`- [ ]`) syntax
> for tracking.

**Goal:** Publish a stable, best-first proxy subscription using multi-sample
health checks, bounded bandwidth observations, EWMA ranking, recovery states,
per-source fallback, and atomic cache guards.

**Architecture:** Extract refresh orchestration from `main` into `internal/pipeline`.
Keep networking in `internal/exitprobe`; place deterministic quality algorithms
and mutable in-memory history in `internal/quality`. Health observations drive
state; normalized EWMA score drives ordering. A separately scheduled bandwidth
stage is bounded to 32 MiB per refresh and cannot affect availability.

**Tech Stack:** Go 1.26, standard library, xray-core library,
`golang.org/x/sync/errgroup`.

## Global Constraints

- Preserve all supported protocols and xHTTP probe behavior; do not reintroduce
  a transport filter.
- No database, cache service, HTTP admin API, or new Go dependency.
- `SUBSCRIPTION_URLS`, proxy credentials, and runtime identity inputs must never
  appear in new logs or output metadata.
- Use TDD: each production behavior begins with a focused failing test.
- `BANDWIDTH_BYTES=1MiB`, `BANDWIDTH_BUDGET_BYTES=32MiB`, concurrency `2`.
- Cache is replaced only at the successful end of a refresh.
- Verify with `go test ./... -race -count=1`, `go vet ./...`, static build, and
  a measured local refresh with the four configured sources.

## File Structure

- Create: `internal/quality/metrics.go`, `scoring.go`, `state.go`, `runtime.go`,
  `bandwidth.go` -- pure quality logic and protected in-memory history.
- Create: `internal/quality/*_test.go` -- algorithm and race-safe snapshot tests.
- Create: `internal/pipeline/pipeline.go` -- refresh composition and publication
  policy; `internal/pipeline/pipeline_test.go` -- source fallback/cache behavior.
- Modify: `internal/config/config.go` -- validated quality configuration.
- Modify: `internal/fetch/fetch.go` -- result classification required for source
  fallback, without logging sensitive URLs.
- Modify: `internal/exitprobe/exitprobe.go` -- geo + health observations and a
  bounded scheduled bandwidth entry point.
- Modify: `cmd/vless-sub-server/main.go` -- composition root and handlers only.
- Modify: `internal/format/format.go` -- aggregate quality header only.
- Modify: `README.md`, `CLAUDE.md` -- configuration and pipeline contract.

### Task 1: Quality Domain and Runtime History

**Files:** Create `internal/quality/{metrics,scoring,state,runtime,bandwidth}.go`
and matching tests.

**Interfaces:**

```go
type Metrics struct { /* sample, geo, bandwidth fields from spec */ }
func Aggregate(samples []time.Duration, failures, requested int, geoOK bool) Metrics
func Score(Metrics, previous float64, hasPrevious bool, now time.Time, lastBW time.Time, cfg ScoringConfig) (raw, ewma float64)
func Transition(RuntimeState, Observation, time.Time, StateConfig) RuntimeState
func SelectBandwidthCandidates([]Runtime, now time.Time, Config) []Runtime
```

- [ ] Write table tests for median/jitter, identity canonicalization, bounded
  score invariants, EWMA cold start, every state transition, budget selection,
  and snapshot copy isolation.
- [ ] Run each test before implementation and confirm it fails because the
  corresponding symbol is absent.
- [ ] Implement each small pure function to turn its test green; no xray or
  HTTP code in this task.
- [ ] Run `go test ./internal/quality -race -count=1` and commit.

### Task 2: Validated Configuration and Source Snapshots

**Files:** Modify `internal/config/config.go`, `internal/fetch/fetch.go`; create
or modify their tests.

**Interfaces:**

```go
type config.QualityConfig struct { /* all environment-backed limits */ }
type fetch.ResultClass int // success, retryable, authoritative-empty
type fetch.SourceCache struct { /* per URL lines + timestamps */ }
func (c *SourceCache) Merge(now time.Time, results []FetchResult, maxAge time.Duration) []string
```

- [ ] Test invalid explicit durations, byte budgets, and ranges before parsing
  is added.
- [ ] Test source fallback for timeout/429/5xx, expiry, cold start, empty 2xx,
  and non-429 4xx.
- [ ] Implement strict config validation and source cache classification.
- [ ] Run `go test ./internal/config ./internal/fetch -race -count=1` and commit.

### Task 3: Health and Bandwidth Observation Stages

**Files:** Modify `internal/exitprobe/exitprobe.go`; extend
`internal/exitprobe/exitprobe_test.go`.

**Interfaces:**

```go
func (ep *ExitProber) ProbeAll(ctx context.Context, records []parse.ProxyRecord) map[int]*ExitProbeResult
func (ep *ExitProber) ProbeBandwidth(ctx context.Context, candidates []ProbeTarget, budget int64) map[string]BandwidthResult
```

- [ ] Write failing tests for five sequential health samples, geo-only partial
  reachability, body/status validation, byte-budget enforcement, truncated
  bandwidth response, and cancellation.
- [ ] Implement health probing through the forced xray outbound with a quality
  target and independent geo result.
- [ ] Implement bandwidth only for pipeline-selected candidates; use a reader
  hard limit and an at-most-two semaphore.
- [ ] Keep all existing outbound-construction tests green; run the package race
  test and commit.

### Task 4: Pipeline, Cache Guards, and Output Ordering

**Files:** Create `internal/pipeline/pipeline.go` and tests; modify
`cmd/vless-sub-server/main.go`, `internal/format/format.go` and its tests.

**Interfaces:**

```go
type Pipeline struct { /* dependencies, source cache, runtime, atomic output */ }
func (p *Pipeline) Refresh(ctx context.Context) RefreshResult
func (p *Pipeline) Cached() (*CachedData, bool)
```

- [ ] Write failing tests for per-source fallback, systemic failure retaining
  cache, no-empty-cache replacement, DEAD-but-still-probed behavior, recovery,
  and equal URL/JSON ordering.
- [ ] Move orchestration to `Pipeline.Refresh`; keep `main` as composition and
  HTTP server only.
- [ ] Format one sorted snapshot into both output formats and add aggregate
  quality metadata.
- [ ] Run the full race suite, vet, static build, and commit.

### Task 5: Documentation and Measured End-to-End Verification

**Files:** Modify `README.md`, `CLAUDE.md`; add no code beyond test-only hooks
needed for deterministic pipeline tests.

- [ ] Document all new environment variables, state semantics, and byte budget.
- [ ] Run a baseline-compatible local service against the four supplied sources;
  measure refresh duration, counts, bandwidth bytes, RSS, and output order.
- [ ] Run all required checks and record exact command results in the final
  delivery; do not claim unmeasured performance.
- [ ] Commit documentation and verification-aligned changes.

