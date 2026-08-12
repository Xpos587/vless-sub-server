# Subscription Views and Country Filter Implementation Plan

> **For agentic workers:** This approved plan is executed inline in the current
> session by the user's explicit instruction. Steps use checkbox (`- [ ]`) syntax
> for tracking.

**Goal:** Add request-specific direct/WARP subscription views whose country
filters use the actually observed final egress of the selected route.

**Architecture:** Keep route-country evidence in the existing per-proxy runtime,
publish one immutable ordered typed snapshot, and render personalized views from
that snapshot. Extend the in-process xray probe with per-proxy WARP outbounds so
country observations traverse the same `proxy -> WARP` chain emitted to users.

**Tech Stack:** Go 1.26, standard library, xray-core, `net/netip`, atomic
in-memory publication.

## Global Constraints

- Preserve existing no-parameter URL output and default WARP JSON behavior.
- Preserve all supported protocols and xHTTP behavior.
- Use exact-chain observed egress; never substitute RIR/ASN/hostname country.
- `warp=on` is accepted only with `format=json`.
- Country-filtered unknown/conflict routes fail closed; unfiltered output stays
  available.
- No new mandatory paid API, database, or Go dependency.
- No proxy IP, credential, source URL, HWID, or canonical identity in public
  headers or new logs.
- Use TDD and observe each focused test fail before production implementation.
- Podman is the container runtime for any container verification.
- Existing local lesson: do not reintroduce the historical xHTTP skip filter.

## File Structure

- Create `internal/country/country.go` and tests: country normalization, family
  state, temporal stabilization, and route filter decisions.
- Create `internal/subview/view.go` and tests: query parsing, snapshot filtering,
  rendering, and aggregate diagnostics.
- Create `internal/warp/config.go`: one internal source of WARP credentials and
  endpoint parameters.
- Create `internal/xhttp/xhttp.go` and tests: lossless official share-link
  codec reused by fetch conversion, probing, and JSON formatting.
- Modify `internal/quality/runtime.go`: retain route-country history.
- Modify `internal/exitprobe/exitprobe.go` and tests: exact direct/WARP country
  observations with `ipwho.is` plus Cloudflare trace fallback.
- Modify `internal/format/xrayjson.go` and tests: WARP-enabled and direct JSON
  variants.
- Modify `internal/pipeline/pipeline.go` and tests: immutable typed cached
  snapshot and country runtime updates.
- Modify `cmd/vless-sub-server/main.go` and add command tests: request view
  integration and HTTP diagnostics.
- Modify `README.md` and `CLAUDE.md`: public contract and operational semantics.

### Task 1: Country domain and query contract

**Produces:**

```go
func country.ParseCodes(values []string) (map[string]struct{}, error)
func country.Observe(previous FamilyResult, observation Observation, now time.Time) FamilyResult
func country.Filter(route RouteCountries, warp bool, excluded map[string]struct{}) Decision
func subview.Parse(url.Values) (Options, error)
```

- [x] Add focused failing table tests for case normalization, repeated values,
  invalid ISO-shaped codes, exact direct/WARP selection, unavailable families,
  fail-closed unknown/conflict, immediate excluded candidates, and two-refresh
  country changes.
- [x] Run `go test ./internal/country ./internal/subview -count=1` and confirm
  failures are caused by missing behavior.
- [x] Implement only the pure domain and parser needed by those tests.
- [x] Run the package race tests for the coherent domain slice.

### Task 2: WARP-aware formatting and shared WARP configuration

**Produces:**

```go
type format.XrayJSONOptions struct { Warp bool }
func format.FormatXrayJSONWithOptions([]rename.RenamedEntry, format.FormatMetadata, format.XrayJSONOptions) []byte
```

- [x] Add failing formatter tests proving default byte/behavior compatibility,
  WARP wireguard/catch-all presence, direct variant wireguard absence, direct
  catch-all routing, and unchanged xHTTP transport output.
- [x] Run the selected tests and confirm the direct option fails before code.
- [x] Move WARP constants into `internal/warp`; implement option-aware outbound
  and routing construction while retaining the compatibility wrapper.
- [x] Add a lossless xHTTP codec for `host/path/mode` plus JSON-object `extra`;
  use it in upstream JSON extraction, probe config, and both JSON variants.
- [x] Add round-trip tests containing XMUX, ranges, download settings, padding,
  and an unknown future field so transport tables cannot silently diverge.
- [x] Run `go test ./internal/format -race -count=1`.

### Task 3: Exact-chain country probing and runtime stabilization

**Produces:**

```go
type exitprobe.CountryObservation struct { IP netip.Addr; Country string }
type ExitProbeResult struct { DirectCountry, WarpCountry CountryObservation /* existing fields */ }
```

- [x] Add failing tests for Cloudflare trace parsing, invalid country/IP
  rejection, WARP outbound `dialerProxy`, one WARP tag per proxy, and fallback
  witness behavior through the same forced outbound tag.
- [x] Run `go test ./internal/exitprobe -count=1` and verify RED.
- [x] Extend the xray config with WARP outbounds and probe the WARP tag after
  direct reachability; keep WARP failure neutral to health state.
- [x] Update runtime country families with `country.Observe`, retaining prior
  values on no observation.
- [x] Run exitprobe/quality/pipeline race tests.

### Task 4: Immutable snapshot, personalized rendering, and HTTP integration

**Produces:**

```go
type pipeline.CachedEntry struct { Entry rename.RenamedEntry; Countries country.RouteCountries }
type pipeline.CachedData struct { Entries []CachedEntry; Metadata format.FormatMetadata /* existing fields */ }
func subview.Render(*pipeline.CachedData, subview.Options) subview.Response
```

- [x] Add failing tests for deep-copy isolation, direct/WARP exclusion,
  unknown/conflict counters, quality-order preservation, valid empty output,
  and no-parameter fast-path equivalence.
- [x] Run selected tests and verify RED.
- [x] Publish typed entries atomically; filter and render only from the cached
  snapshot; wire validation and aggregate headers into the HTTP handler.
- [x] Run command, subview, pipeline, and full race tests.

### Task 5: Documentation and measured local verification

- [x] Document query examples, defaults, fail-closed semantics, exact WARP
  country meaning, and diagnostic headers in `README.md` and `CLAUDE.md`.
- [x] Run race tests, vet, and static build.
- [x] Start the service with the supplied env without logging secret values and
  wait for a completed refresh.
- [x] Measure default/direct/WARP counts, excluded-country counts, headers,
  refresh duration, and country unknown/conflict totals.
- [x] Inspect generated JSON for WARP-on/off routing and validate representative
  exact-chain egress observations.
- [x] Fix failures through focused TDD loops and rerun all checks; leave the
  verified changes uncommitted unless the user explicitly asks for a commit.
