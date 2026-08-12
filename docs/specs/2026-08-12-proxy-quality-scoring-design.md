# Proxy quality probing, scoring, and recovery design

> Date: 2026-08-12
>
> Status: approved direction. This document defines the implementation contract;
> it does not include implementation changes.

## 1. Intent

The service currently decides whether to publish a proxy from one successful
`ipwho.is` request. That proves basic reachability, but it does not distinguish a
stable proxy from one that is intermittently failing, highly variable, or too
slow for normal use. It also makes the subscription order depend on upstream
order rather than measured quality.

The new pipeline must produce a stable, best-first subscription while preserving
the service's current strengths: one small Go process, no database, atomic cached
output, xray-core in-process, and support for foreign subscription sources that
we do not control.

The human outcome is simple: clients should connect to useful proxies first and
should see less churn from one-off failures. The service must not achieve that by
creating an uncontrolled speed-test workload or by deleting temporarily failing
proxies from the recovery loop.

Experience invariants:

- `/sub` and `/sub?format=json` remain fast cache reads.
- A transient probe or upstream failure does not wipe a previously good
  subscription.
- Consistently healthy proxies appear before unstable proxies.
- A DEAD proxy is absent from output but remains eligible for future recovery.
- Bandwidth measurement has a hard global byte budget and cannot grow linearly
  without limit as the subscription grows.
- Credentials, canonical proxy identities, and source tokens are never exposed
  through quality logs or output metadata.

Betrayal condition: the implementation reports sophisticated scores but makes
the actual subscription less reliable, causes excessive traffic, or mistakes an
outage of the measurement provider for the death of every proxy.

## 2. Scope

This change adds five tightly related capabilities:

1. Multiple lightweight HTTP health samples per proxy.
2. Bounded quality scoring with EWMA smoothing.
3. A per-proxy availability state machine.
4. An in-memory runtime store that survives refresh cycles.
5. A globally budgeted, rotating short-transfer bandwidth probe.

It also adds publication safeguards and per-source stale fallback because quality
state is not useful if a temporary upstream fetch failure removes half the input
before probing begins.

Out of scope:

- PostgreSQL, Redis, or any other persistent state service.
- An admin API or UI for tuning weights.
- Upload speed, UDP packet loss, TURN, loaded latency, BGP, conntrack, nftables,
  or control of entry nodes.
- A user-visible per-proxy score embedded in proxy names.
- Persisting quality history across process restarts.
- Replacing `ipwho.is` geolocation in this phase.

## 3. Considered approaches

### A. N-sample reachability only

Run several requests, calculate latency/loss/jitter, sort the current refresh,
and keep no history. This is small, but subscription order still oscillates and a
single bad refresh can remove an otherwise reliable proxy.

### B. Balanced quality loop with a bandwidth budget — selected

Keep per-proxy runtime state, smooth scores, apply explicit recovery states, and
test short-transfer throughput for a rotating subset under a global byte budget.
This adds meaningful stability while preserving the current single-process
architecture.

### C. Full speed test for every proxy

Run ramp-up downloads similar to a browser speed-test engine for every proxy on
every refresh. This gives more accurate line-rate estimates, but is inappropriate
for an aggregator of foreign proxies. At 125 live proxies, a 5 MiB test is up to
625 MiB per full pass and up to 30 GiB/day at a 30-minute cadence.

Decision: implement B. Bandwidth is a secondary, confidence-limited signal, not
the dominant definition of proxy quality.

## 4. Resulting pipeline

```text
fetch current sources
  -> merge with per-source stale fallback
  -> parse and deduplicate
  -> DNS resolve
  -> start xray probe instance
  -> geo probe + 5 health samples for every active proxy
  -> reject a systemic measurement failure
  -> select rotating bandwidth candidates under global budget
  -> run bounded bandwidth stage
  -> update metrics, EWMA, and state machine
  -> take one immutable runtime snapshot
  -> exclude DEAD, sort best-first
  -> rename and format URL + JSON output
  -> publication guard
  -> atomic cache swap
```

`handleSub` does not read the runtime store and does not calculate scores. Both
output formats are built from the same ordered snapshot and stored atomically.

## 5. Package boundaries

The orchestration currently lives in `cmd/vless-sub-server/main.go`. Quality
logic must not make that file responsible for algorithms and mutable state.

### `internal/quality`

Pure domain logic with no networking:

- metric aggregation;
- normalized score calculation;
- EWMA;
- state transitions;
- runtime identity generation;
- bandwidth candidate selection.

Suggested files:

```text
internal/quality/
  metrics.go      // observations and sample aggregation
  scoring.go      // bounded score and EWMA
  state.go        // HEALTHY/DEGRADED/DEAD/RECOVERING
  runtime.go      // runtime store, identity, snapshots, retention
  bandwidth.go    // budgeted oldest-first candidate selection
```

### `internal/exitprobe`

Owns xray-core and network measurements. It returns observations; it does not
decide state, score, output order, or publication policy.

### `internal/pipeline`

New orchestration package extracted from `main.go`. It owns source fallback,
refresh execution, systemic-failure detection, runtime updates, snapshot
construction, and publication decisions. The command package remains the
composition root and HTTP server.

This extraction is part of the feature, not a general refactor. Existing parse,
DNS, rename, and format packages retain their current contracts unless the plan
identifies a minimal adapter.

## 6. Stable proxy identity

Runtime state must not be keyed only by `host:port`. Two proxies can share an
address while differing in credentials, SNI, encryption, or transport.

Build a canonical identity from:

```text
protocol NUL host NUL port NUL credential NUL sorted(query-key=query-value)
```

Rules:

- Normalize the host to lowercase and remove IPv6 presentation brackets.
- Include every parsed query parameter because any parameter may affect the
  xray outbound behavior.
- Sort query keys bytewise; preserve values exactly after parser normalization.
- Exclude `Fragment` and `OriginalLine`; display names do not define identity.
- Hash the canonical bytes with SHA-256 and use the lowercase hex digest as the
  map key.
- Never log the canonical input or raw credential. Logs may include at most a
  short non-security identifier derived from the first 8 hex characters when
  correlation is necessary.

A changed credential or transport creates a new runtime identity. Entries not
seen in the active input set are retained for 48 hours for diagnostics and then
garbage-collected, but they are never emitted unless their identity is active in
the current merged source snapshot.

## 7. Source fallback

Each configured subscription URL gets an in-memory source entry:

```go
type SourceSnapshot struct {
    Lines         []string
    LastSuccess   time.Time
    LastErrorKind string // sanitized category, never a URL or response body
}
```

On a successful non-empty `2xx` fetch, replace that source's snapshot. On a
transport error, timeout, `429`, or `5xx`, reuse its last successful lines for up
to `SOURCE_STALE_MAX_AGE` (default `6h`). On cold start there is no fallback for
a source that has never succeeded.

Other `4xx` responses and a successfully decoded empty `2xx` response are
authoritative: clear the source's active lines instead of reviving stale
credentials. The whole-output publication guard still prevents an accidental
all-source collapse from replacing an existing non-empty cache.

This is per-source fallback, not whole-output fallback. A successful source can
add/remove proxies immediately while an unrelated timed-out source retains its
last known input.

Do not treat a proxy missing because its source snapshot expired as a probe
failure. It simply leaves the active identity set; its runtime entry ages out
independently.

## 8. Health and geolocation probes

### Separate geolocation from quality samples

The existing `ipwho.is` request remains the geolocation request. It is executed
once per proxy per refresh and may also demonstrate that the outbound can reach
the public internet. Its timing is not included in latency or jitter because the
quality samples must target the same endpoint to be comparable.

If geolocation fails but health samples succeed, preserve the last known geo
record from runtime state. A geo-provider failure must not kill a working proxy.

### Health target and sample method

Use Cloudflare's documented download endpoint:

```text
GET https://speed.cloudflare.com/__down?bytes=0
```

Cloudflare's own speed-test engine uses `bytes=0` requests for latency. Each
sample uses a fresh HTTP transport with keep-alives disabled, so the measured
value represents complete request setup through the proxy rather than a lucky
reused connection.

Default sampling:

| Setting | Default |
|---|---:|
| `PROBE_SAMPLE_COUNT` | `5` |
| `PROBE_SAMPLE_GAP` | `100ms` |
| `PROBE_SAMPLE_TIMEOUT` | `5s` |
| `MAX_CONCURRENT` | existing `50` |

Samples for one proxy run sequentially. Proxies run concurrently under the
existing global `MAX_CONCURRENT` limit, so in-flight work remains bounded by 50,
not `50 * sample_count`.

Successful sample requirements:

- HTTP request completed before timeout;
- status is `200`;
- response body is drained and closed;
- requested `bytes=0` response is accepted only when its body is empty.

The measured latency is start-to-response-header duration. Store individual
successful durations for aggregation.

### Metrics

```go
type Metrics struct {
    SampleCount       int
    SuccessCount      int
    GeoOK             bool    // ipwho.is succeeded through this outbound
    InternetReachable bool    // GeoOK or at least one health sample succeeded
    RequestLatencyMS  float64 // median of successful samples
    MinLatencyMS      float64
    MaxLatencyMS      float64
    FailurePct        float64 // failed HTTP samples / requested samples
    JitterMS          float64 // mean absolute delta between consecutive successes
    Blackhole         bool    // neither geo nor any health sample succeeded
    DownloadMbps      float64
    BandwidthMeasured bool
    BandwidthFresh    bool
}
```

`FailurePct` is deliberately not called network packet loss. HTTP request
failure is an application-path availability signal; true packet loss would
require a different transport and measurement method.

`InternetReachable` deliberately has two independent witnesses. A proxy that
reaches `ipwho.is` but blocks Cloudflare is not a blackhole: it is reachable but
cannot be fully characterized by the selected quality provider. It remains
DEGRADED and sorts near the end instead of transitioning to DEAD solely because
one measurement domain is unavailable.

Use median latency rather than mean so one timeout-adjacent sample does not
dominate an otherwise consistent proxy. Jitter follows Cloudflare's documented
method: average absolute distance between consecutive latency measurements.

## 9. Bandwidth probe

### Meaning

The feature measures short-transfer throughput, not theoretical line capacity.
That is the useful quantity for clients downloading normal web resources through
a proxy, and it can be measured with a bounded workload.

Target:

```text
GET https://speed.cloudflare.com/__down?bytes=1048576
```

Cloudflare returns `Cache-Control: no-store, no-transform` and an exact content
length. The implementation must require status `200` and an exact matching
`Content-Length`, then read exactly the expected number of bytes through a hard
limit. A shorter body is rejected; a declared oversized body is rejected before
reading payload bytes.

### Measurement interval

Use `httptrace.GotFirstResponseByte` to separate setup/TTFB from payload transfer.
Calculate:

```text
download_mbps = bytes_received * 8 / payload_duration_seconds / 1,000,000
```

where payload duration starts at the first response byte and ends after the
expected body has been read. Record total request duration separately for logs,
but do not use it as bandwidth.

This choice is based on both Cloudflare's methodology (transfer size divided by
request duration, excluding server processing where possible) and an HTTP
measurement from the current host on 2026-08-12. Three 1,000,000-byte requests had total durations
`1.699s`, `1.728s`, and `1.631s`, while TTFB was `0.759s`, `0.704s`, and
`0.546s`. Including TTFB would have materially understated payload throughput.

Reproduction command:

```bash
for run in 1 2 3; do
  curl -sS --max-time 20 -o /dev/null \
    -w 'ttfb=%{time_starttransfer} total=%{time_total} speed=%{speed_download}\n' \
    'https://speed.cloudflare.com/__down?bytes=1000000'
done
```

### Global scheduling and budget

Bandwidth probes are selected before downloads start. A cached throttle that is
checked only after downloading is invalid and must not be implemented.

Defaults:

| Setting | Default |
|---|---:|
| `BANDWIDTH_ENABLED` | `true` |
| `BANDWIDTH_BYTES` | `1048576` (1 MiB) |
| `BANDWIDTH_BUDGET_BYTES` | `33554432` (32 MiB/refresh) |
| `BANDWIDTH_MAX_CONCURRENT` | `2` |
| `BANDWIDTH_TIMEOUT` | `8s` |
| `BANDWIDTH_STAGE_TIMEOUT` | `45s` |
| `BANDWIDTH_REFRESH_AFTER` | `2h` |
| `BANDWIDTH_RETRY_AFTER` | `30m` |
| `BANDWIDTH_STALE_AFTER` | `6h` |

The candidate count is:

```text
min(floor(remaining_budget / bytes_per_probe), eligible_due_candidates)
```

Candidate priority is deterministic:

1. Active and currently reachable proxies that have never had a successful
   bandwidth sample.
2. Proxies with the oldest successful bandwidth sample older than
   `BANDWIDTH_REFRESH_AFTER`.
3. Stable identity as the tie-breaker.

Only proxies with at least one successful health sample in the current refresh
are bandwidth-eligible. DEAD and current-blackhole proxies are excluded.
Candidates must also satisfy the attempt throttle: never-attempted, or
`now - LastBandwidthAttemptAt >= BANDWIDTH_RETRY_AFTER`. A successful value is
due for refresh only after `BANDWIDTH_REFRESH_AFTER`.

The stage stops when any one limit is reached: byte budget, candidate exhaustion,
or stage timeout. Concurrency `2` balances wall time against self-interference on
the host's own network path.

Track `LastBandwidthAttemptAt` separately from `LastBandwidthSuccessAt`. A failed
attempt:

- does not erase the previous successful value;
- does not mark the proxy unhealthy;
- is retried no sooner than `BANDWIDTH_RETRY_AFTER`;
- leaves bandwidth neutral once the previous value becomes stale.

The runtime counter `BandwidthBytesThisRefresh` must be based on bytes actually
read and must never exceed the configured budget. The HTTP body reader itself is
also limited to the remaining budget so scheduler mistakes cannot overspend it.

## 10. Bounded scoring

Do not copy outward's raw-unit formula literally. Adding milliseconds,
percentages, jitter, and Mbps with arbitrary coefficients makes the relative
importance difficult to reason about and allows an extreme bandwidth result to
hide serious instability.

Normalize each component to `[0, 1]`, then calculate a score in `[0, 100]` where
lower is better:

```text
latency_cost  = clamp((median_latency_ms - 100) / 900, 0, 1)
failure_cost  = clamp(failure_pct / 100, 0, 1)
jitter_cost   = clamp(jitter_ms / 300, 0, 1)

bandwidth_quality = clamp(log1p(download_mbps) / log1p(100), 0, 1)
bandwidth_cost    = 1 - bandwidth_quality
```

If bandwidth is missing or older than `BANDWIDTH_STALE_AFTER`, use neutral
`bandwidth_cost = 0.5`. A failed bandwidth request is not a zero-speed result.

```text
raw_score = 100 * (
    0.35 * latency_cost
  + 0.40 * failure_cost
  + 0.15 * jitter_cost
  + 0.10 * bandwidth_cost
)
```

Properties that tests must enforce:

- Increasing failure percentage cannot improve score.
- Increasing latency or jitter cannot improve score.
- Increasing fresh bandwidth cannot worsen score.
- Bandwidth can change at most 10 points of the 100-point score.
- A missing bandwidth result is neutral, not best and not worst.
- Score is finite and clamped to `[0, 100]` for all inputs.

Smooth the resulting score across refreshes:

```text
score_ewma = alpha * raw_score + (1 - alpha) * previous_ewma
```

Default `SCORING_EWMA_ALPHA=0.35`. Cold start uses an explicit `HasScore` boolean;
zero is a valid excellent score and must not be overloaded as an uninitialized
sentinel.

The state machine uses current availability observations, not EWMA. EWMA controls
ordering, not whether a blackholed proxy is considered successful.

A BLACKHOLE observation has no meaningful current latency or jitter. It updates
availability state and timestamps but preserves the previous raw score and EWMA.
It must never be scored as zero latency.

If geo succeeds but all health samples fail, the proxy receives a conservative
raw score of `95`: latency cost `1`, failure cost `1`, jitter cost `1`, and
neutral bandwidth cost `0.5`. This lets a new geo-only proxy remain eligible at
the end of the subscription without inventing zero-millisecond latency. A new
proxy with neither geo nor a successful health sample has no score and is
ineligible for output.

## 11. State machine

States:

```text
HEALTHY -> DEGRADED -> DEAD -> RECOVERING -> HEALTHY
```

Observation classes per refresh:

- `GOOD`: at least 4 of 5 health samples succeeded.
- `PARTIAL`: 1 to 3 health samples succeeded, or geo succeeded while every
  health sample failed.
- `BLACKHOLE`: neither geo nor any health sample succeeded.

For non-default sample counts, `GOOD` means health success ratio `>= 0.8`,
`PARTIAL` means health success ratio `> 0` or `GeoOK`, and `BLACKHOLE` means both
health success ratio zero and `GeoOK=false`.

Transitions:

| Current | Observation | Next state / action |
|---|---|---|
| new | GOOD | HEALTHY |
| new | PARTIAL | DEGRADED |
| new | BLACKHOLE | DEGRADED, not output because no last success exists |
| HEALTHY | GOOD | HEALTHY; clear failure counters |
| HEALTHY | PARTIAL | DEGRADED |
| HEALTHY | BLACKHOLE | DEGRADED; increment consecutive blackholes |
| DEGRADED | GOOD twice consecutively | HEALTHY |
| DEGRADED | PARTIAL | DEGRADED; reset consecutive-good only |
| DEGRADED | BLACKHOLE twice consecutively | DEAD |
| DEAD | GOOD before cooldown | DEAD; update last success, keep recovery counter at zero |
| DEAD | first GOOD after `30m` cooldown | RECOVERING; consecutive-good = 1 |
| DEAD | PARTIAL/BLACKHOLE | DEAD; reset recovery successes |
| RECOVERING | next consecutive GOOD | HEALTHY |
| RECOVERING | PARTIAL | DEGRADED |
| RECOVERING | BLACKHOLE | DEAD |

Defaults:

```text
DEAD_BLACKHOLE_THRESHOLD=2
RECOVERY_SUCCESS_THRESHOLD=2
DEAD_COOLDOWN=30m
```

A DEAD proxy remains in the active probe set as long as its identity remains in
the merged sources. DEAD affects output only.

Blackhole counters continue across the `HEALTHY -> DEGRADED` transition: the
first consecutive blackhole sets the count to one, and the second transitions
the proxy to DEAD. Recovery requires two consecutive GOOD observations after
the cooldown: the first enters RECOVERING and the second enters HEALTHY.

### Output eligibility

- HEALTHY, DEGRADED, and RECOVERING are eligible.
- DEAD is never eligible.
- A proxy must have succeeded at least once since process start.
- Last successful health observation must be no older than `90m`.

The 90-minute grace allows one blackhole refresh without immediate output churn,
while two consecutive 30-minute blackholes transition to DEAD and remove the
proxy. On process restart there is no grace for a proxy that has not yet
succeeded.

## 12. Runtime store

```go
type Runtime struct {
    Key                       string
    Record                    parse.ProxyRecord
    Geo                       *geo.GeoInfo
    Metrics                   quality.Metrics
    RawScore                  float64
    ScoreEWMA                 float64
    HasScore                  bool
    State                     quality.State
    ConsecutiveBlackholes     int
    ConsecutiveGood           int
    StateChangedAt            time.Time
    DeadAt                    time.Time
    LastSeenAt                time.Time
    LastHealthSuccessAt       time.Time
    LastBandwidthAttemptAt    time.Time
    LastBandwidthSuccessAt    time.Time
    LastBandwidthMbps         float64
}
```

The store uses `RWMutex` and owns copies of mutable records/maps. Callers cannot
mutate stored entries through returned pointers. A refresh updates entries and
then requests one immutable snapshot for sorting and formatting.

The store is intentionally process-local. After restart, scores and states cold
start, but the existing published cache is also process-local, so this does not
introduce a new durability inconsistency. Persistence can be reconsidered only
if multiple replicas or restart-stable ranking becomes a real requirement.

## 13. Sorting and naming

Eligible proxies sort by:

1. State rank: `HEALTHY`, `RECOVERING`, `DEGRADED`.
2. `ScoreEWMA` ascending.
3. Current median request latency ascending.
4. Stable identity ascending for deterministic ties.

Renaming happens after sorting. Therefore the best proxy for an otherwise
identical `flag + city + ISP` name keeps the unsuffixed base name, and lower
ranked duplicates receive `(2)`, `(3)`, and so on.

Both URL and JSON formatters receive the same ordered `[]rename.RenamedEntry`.
Formatters do not read runtime state.

## 14. Systemic failure and publication safety

Per-proxy state must not be updated when the measurement system itself is
clearly broken.

Classify a health-probe phase as systemic failure when all conditions hold:

- at least 20 active proxies were submitted;
- fewer than 5% produced any successful health sample;
- the previous published output was non-empty.

Also classify as systemic failure when xray configuration build/start fails or
the refresh context expires before the health phase completes.

On systemic failure:

- do not apply BLACKHOLE transitions;
- do not run bandwidth probes;
- do not replace output cache;
- retain the previous cache and runtime metrics;
- log one aggregate error with counts and duration.

Publication is also rejected when a newly built output is empty while the
previous output is non-empty. An intentionally empty first-ever subscription may
still publish only when parsing produced no active proxy records from at least
one successfully fetched source; otherwise the service remains initializing and
returns its existing `503` behavior.

No generic percentage-collapse guard is added. Per-source stale fallback and the
systemic probe gate address known accidental-collapse modes without preventing a
legitimate mass removal by upstream providers.

## 15. Configuration

Keep tuning in environment variables. There is no DB or runtime mutation API.

New variables:

| Variable | Default | Validation |
|---|---:|---|
| `SOURCE_STALE_MAX_AGE` | `6h` | `>= 0` |
| `PROBE_SAMPLE_COUNT` | `5` | `1..10` |
| `PROBE_SAMPLE_GAP` | `100ms` | `0..2s` |
| `PROBE_SAMPLE_TIMEOUT` | `5s` | `> 0` |
| `SCORING_EWMA_ALPHA` | `0.35` | `(0,1]` |
| `BANDWIDTH_ENABLED` | `true` | boolean |
| `BANDWIDTH_BYTES` | `1048576` | `64KiB..8MiB` |
| `BANDWIDTH_BUDGET_BYTES` | `33554432` | `>= BANDWIDTH_BYTES` when enabled |
| `BANDWIDTH_MAX_CONCURRENT` | `2` | `1..8` |
| `BANDWIDTH_TIMEOUT` | `8s` | `> 0` |
| `BANDWIDTH_STAGE_TIMEOUT` | `45s` | `> 0` |
| `BANDWIDTH_REFRESH_AFTER` | `2h` | `> 0` |
| `BANDWIDTH_RETRY_AFTER` | `30m` | `> 0` |
| `BANDWIDTH_STALE_AFTER` | `6h` | `>= BANDWIDTH_REFRESH_AFTER` |
| `RUNTIME_RETENTION` | `48h` | `> 0` |

Invalid values fail startup with a field-specific error. Do not silently replace
invalid explicit values with defaults.

The existing overall refresh timeout must increase from `2m` to `3m` to include
the bounded bandwidth stage. The normal target remains well below the timeout;
the timeout is a safety ceiling, not a performance objective.

## 16. Output metadata and logging

Extend text subscription metadata with aggregate quality information:

```text
# Quality: 90 healthy, 4 recovering, 20 degraded, 11 dead
# Bandwidth: 32 tested this refresh, 118 fresh, 32.0 MiB downloaded
```

`TotalAlive` means emitted entries. `TotalDead` means active identities currently
in DEAD state; DNS failures and inactive/expired source entries are reported
separately in logs rather than conflated with DEAD.

Refresh completion log fields:

- fetched/parsed/DNS-resolved counts;
- GOOD/PARTIAL/BLACKHOLE counts;
- state counts and transitions;
- bandwidth candidates, successes, failures, bytes, and stage duration;
- emitted count and whether cache was published;
- total refresh duration.

Do not log raw proxy URLs, credentials, canonical identity input, exit IPs, or
bandwidth response bodies as part of this feature.

`/health` remains liveness-only and returns `ok`. Readiness/quality endpoints are
not added in this phase.

## 17. Concurrency and resource handling

- One refresh remains active at a time through the existing atomic guard.
- Health probes use `errgroup.SetLimit(MAX_CONCURRENT)`.
- Samples within one proxy are sequential.
- Bandwidth probes use a separate semaphore limited by
  `BANDWIDTH_MAX_CONCURRENT` and start only after health candidate selection.
- Every request has both context cancellation and a client timeout.
- Every response body is bounded, drained where appropriate, and closed.
- Bandwidth readers are limited by both expected response size and remaining
  global budget.
- Xray instance shutdown is deferred so all early returns close it.
- Runtime/source cache locks are never held during network I/O.

## 18. Failure handling

| Failure | Required behavior |
|---|---|
| Source timeout, transport error, 429, or 5xx | Use fresh per-source snapshot; continue refresh |
| Source 4xx other than 429, or decoded empty 2xx | Treat source as authoritatively empty; do not use stale lines |
| Source stale snapshot older than 6h | Drop that source from active input without marking proxies failed |
| DNS failure | Skip current probe; do not mutate prior runtime state as BLACKHOLE |
| Geo request failure, health succeeds | Preserve last geo; proxy remains reachable |
| Geo succeeds, all Cloudflare health samples fail | PARTIAL, conservative score 95; never DEAD for this condition alone |
| Some health samples fail | PARTIAL observation; calculate bounded score |
| All samples fail for one proxy | BLACKHOLE transition; retain prior output only within state grace |
| Nearly all proxies fail together | Systemic failure; keep old cache and runtime |
| Bandwidth timeout/error | Preserve previous value; neutral when stale; health unaffected |
| Bandwidth stage timeout | Publish completed health results and successful bandwidth samples |
| Empty new output with prior cache | Reject publication and retain old cache |
| Panic during refresh | Existing recovery logs panic; cache remains untouched because swap is last |

## 19. Testing strategy

### Unit tests

`internal/quality` must be network-free and table-tested:

- canonical identity equality and inequality across fragment, credentials,
  query parameters, IPv6, and query ordering;
- metric aggregation for all-success, partial, single-success, and blackhole;
- median and jitter calculations;
- scoring monotonic invariants and `[0,100]` bounds;
- EWMA cold start with `HasScore`, convergence, and alpha edges;
- every state transition, cooldown, counter reset, and restart cold state;
- output eligibility grace and DEAD exclusion;
- bandwidth oldest-first selection, deterministic ties, retry throttle, stale
  values, byte budget, and zero eligible candidates;
- runtime snapshot copy isolation and retention cleanup;
- source fallback success, failure, expiry, and cold start.

### Exit probe tests

Use `httptest` where xray routing is not the subject:

- exact sample count and timeout behavior;
- status/body validation;
- geo failure independent from health success;
- `httptrace` first-byte measurement;
- exact bandwidth byte count, truncation rejection, and hard reader limit;
- cancellation closes requests and does not leak goroutines.

Existing outbound-construction tests remain mandatory for every supported
protocol.

### Pipeline tests

- DEAD remains in probe input but not output.
- URL and JSON output have identical ordering.
- a partial upstream fetch reuses only the failed source's snapshot;
- systemic measurement failure does not mutate runtime or cache;
- bandwidth failure does not reduce health state;
- cache swap occurs once and only after both outputs are formatted;
- a successful legitimate upstream mass removal can publish;
- empty accidental output cannot replace a non-empty cache.

### Verification commands

```bash
go test ./... -race -count=1
go vet ./...
CGO_ENABLED=0 go build -ldflags='-s -w' -o /tmp/vless-sub-server ./cmd/vless-sub-server
```

Run a real local refresh with the existing four sources and record, rather than
estimate:

- total refresh duration;
- active/resolved/GOOD/PARTIAL/BLACKHOLE/emitted counts;
- bandwidth candidates/successes/bytes/stage duration;
- process RSS before and after refresh;
- URL and JSON output counts and ordering consistency.

The implementation PR must include the exact reproduction command and a measured
before/after table. Performance claims without measurements are prohibited.

## 20. Acceptance criteria

The feature is complete when:

1. Every active DNS-resolved proxy receives the configured number of bounded
   health samples unless its context is cancelled.
2. Output is deterministically ordered by state and EWMA score.
3. DEAD proxies are omitted from both formats but continue to be probed.
4. A proxy can transition from DEAD back to HEALTHY through RECOVERING without
   restarting the process.
5. Bandwidth bytes actually read never exceed `BANDWIDTH_BUDGET_BYTES` per
   refresh.
6. Bandwidth scheduling skips fresh/throttled proxies before any download starts.
7. Missing or failed bandwidth data is neutral and cannot make a proxy DEAD.
8. A systemic measurement outage and an empty accidental refresh preserve the
   prior cache.
9. Per-source fallback prevents a temporary source timeout from immediately
   removing its previous proxies.
10. URL and JSON subscriptions contain the same eligible proxies in the same
    quality order.
11. Existing protocol parsing, reconstruction, WARP JSON chaining, and v2rayNG
    `inbounds` compatibility tests remain green.
12. Race tests, vet, static build, and the measured local end-to-end run pass.

## 21. Risks and mitigations

### Tigers — evidence-backed threats

- **Bandwidth traffic grows with proxy count.** Mitigation: global byte budget,
  pre-download scheduling, body limits, and oldest-first rotation.
- **Concurrent speed tests measure the host bottleneck rather than the proxy.**
  Mitigation: concurrency defaults to 2 and bandwidth weight is capped at 10%.
- **Measurement endpoint outage looks like proxy death.** Mitigation: systemic
  failure gate and old-cache retention.
- **Upstream source timeout causes subscription collapse.** Mitigation:
  per-source stale snapshots.
- **A raw cost formula lets bandwidth overpower availability.** Mitigation:
  normalized bounded components with failure as the largest weight.

### Paper tigers

- **In-memory history is lost on restart.** This produces a temporary cold start,
  not data corruption; refresh rebuilds state. Persistence is unnecessary for a
  single replica today.
- **Five samples are not statistically exhaustive.** They are sufficient for
  detecting obvious instability within the refresh budget; the design does not
  claim laboratory-grade network measurement.

### Elephants — assumptions to verify during implementation

- Cloudflare may rate-limit or alter the undocumented operational behavior of
  `__down`, even though it is the endpoint documented by its open-source
  speed-test engine. If real runs show systemic throttling, keep the target behind
  one internal constant/interface so a second provider can be added without
  changing scoring.
- The VPS network path may be the limiting factor for many proxies. If measured
  bandwidth clusters tightly or changes with probe concurrency, reduce bandwidth
  weight or concurrency based on evidence.
- A 1 MiB short transfer may be too brief on very fast proxies. If payload
  durations are consistently below 250ms, a future adaptive ramp can spend 2 MiB
  for those candidates while remaining inside the same global budget. Adaptive
  ramping is not part of this implementation.

## 22. References

- Existing RouteBrain adaptation in outward:
  `../../../outward/docs/specs/2026-07-06-pipeline-quality-probing-design.md`.
- Outward implementation commits: `97f6087` (N-sample + bandwidth), `3499770`
  (scoring/EWMA), `21c03bd` (state), `efc048d` (runtime), `548857d`
  (integration). The outward bandwidth throttle is not copied because its current
  implementation downloads before the runtime-layer throttle check.
- Cloudflare Speedtest README and measurement methodology:
  <https://github.com/cloudflare/speedtest>.
- Cloudflare download endpoint: <https://speed.cloudflare.com/__down>.
