# Subscription views and route-country filtering design

> Date: 2026-08-12
>
> Status: approved for inline implementation by the user.

## 1. Intent

The subscription endpoint must support request-specific views without rerunning
the refresh pipeline:

```text
/sub?warp=off&exclude=fi,ro,ru,by
/sub?format=json&warp=on&exclude=fi,ro,ru,by
```

The important product meaning is not "where is the proxy server registered?".
It is "which country will the destination website perceive for this exact
route?". For a direct link this is the direct proxy egress. For a WARP profile
this is the final egress after `client -> proxy -> WARP -> Internet`.

The implementation must reduce unknown countries without inventing certainty.
RIR registration country, ASN headquarters, reverse DNS, the proxy hostname,
and the WARP connected colo are not substitutes for an observed final egress.

Experience invariants:

- Existing `/sub` URL output remains unchanged when no parameters are supplied.
- Existing `/sub?format=json` keeps WARP enabled by default.
- `warp=on` filters on the final WARP egress, not the direct proxy country.
- Country filtering never exposes proxy IPs, credentials, source URLs, or HWID.
- A failed geo provider does not erase a previously confirmed country.
- A filtered empty result is valid and must not be confused with a failed
  refresh or replace the global cache.
- URL and JSON views preserve the quality ordering from the published snapshot.

Betrayal condition: the endpoint claims to exclude a country while filtering on
the server location, Cloudflare colo, or direct proxy country for a WARP chain.

## 2. Public query contract

Supported parameters:

```text
format=url|json
warp=on|off
exclude=CC[,CC...]
```

Rules:

- `format` defaults to `url`.
- `warp` defaults to `off` for URL and `on` for JSON, preserving current output.
- `warp=on` with `format=url` returns `400`; URL proxy links cannot encode the
  second WARP hop.
- `exclude` accepts case-insensitive ISO 3166-1 alpha-2 codes, trims whitespace,
  uppercases and deduplicates them.
- A malformed country code returns `400`; silent partial filtering is unsafe.
- Repeated `exclude` parameters are merged.
- Unknown query parameters remain ignored for backward compatibility.

Successful responses include only aggregate diagnostics:

```text
X-Warp: on|off
X-Country-Filtered: <count>
X-Country-Unknown: <count>
X-Country-Conflict: <count>
```

No diagnostic contains an address or proxy identity.

## 3. Country dimensions

Country is stored as route-specific evidence, not as one field:

```text
direct IPv4 country
direct IPv6 country
WARP IPv4 country
WARP IPv6 country
```

Optional operational diagnostics such as physical egress or connected colo are
separate dimensions and do not participate in `exclude`.

Selection is exact:

```text
warp=off -> direct family results
warp=on  -> WARP family results
```

If any actually observed address family belongs to an excluded country, the
entry is removed. An address family never observed for that route is
`unavailable`, not `unknown`, and does not block the other family.

When `exclude` is absent, unresolved country evidence never hides a proxy. When
`exclude` is present, a route with no usable country or with conflicting current
evidence fails closed and is omitted.

## 4. Evidence model

The primary evidence is an HTTP request sent through the exact xray outbound
tag. The response must report the source address and country perceived at the
destination side.

Initial witnesses are ordered by route type:

1. Direct routes use `ipwho.is` first because it also supplies city and ISP,
   then Cloudflare `cdn-cgi/trace` as the country fallback.
2. WARP routes use Cloudflare trace first because Cloudflare is authoritative
   for the source address and `loc` perceived at its own WARP edge, then
   `ipwho.is`, then `api.country.is`, as independent fallbacks.

Only the trace `ip` and `loc` fields are parsed. `colo` is deliberately not
treated as egress country. After the health samples warm a reachable route, one
trace-only retry is allowed for country evidence that is still missing.

This fallback materially reduces cold-start unknowns while avoiding a mandatory
paid API. A later phase may add a non-Cloudflare owned witness and commercial
local databases as corroboration. Provider count alone is not confidence:
multiple services may share the same upstream database.

Cloudflare's RFC 8805 geofeed is useful operator evidence for Cloudflare-owned
WARP addresses, but it is not required in the first implementation. It should be
added as a cached, stale-tolerant corroborator rather than downloaded in every
refresh or used without an observed source IP.

## 5. Country state and stabilization

Each family result records:

```go
type FamilyResult struct {
    Available        bool
    IP               netip.Addr
    Country          string
    ObservedCountry  string
    Status           Status // CONFIRMED, CONFLICT, UNKNOWN
    CandidateCountry string
    CandidateCount   int
    ConfirmedAt      time.Time
    ObservedAt       time.Time
}
```

Transition rules:

- The first valid exact-chain observation establishes the country immediately.
- Repeating the current country keeps it confirmed and clears a candidate.
- One different country creates `CONFLICT` and retains the last confirmed
  country as historical context.
- The same different country on the next refresh confirms the change.
- A failed observation retains the previous result; it does not manufacture an
  `UNKNOWN` event.
- A newly observed excluded country removes the route immediately, including
  the first conflicting observation.
- Returning from an excluded country requires two matching observations, so a
  one-off provider error cannot reopen a prohibited route.

Runtime country history remains in memory across refreshes and is keyed by the
same credential-sensitive proxy identity used by quality scoring.

When `COUNTRY_STATE_PATH` is configured, route-country evidence also survives a
process restart. The file is atomically replaced with mode `0600` and contains
only opaque identity hashes and the route-country state; proxy endpoints,
credentials, and subscription URLs are not persisted.

## 6. Exact WARP-chain probing

The probe xray instance gets two tags per proxy:

```text
proxy_N_out
warp_N_out (wireguard with dialerProxy=proxy_N_out)
```

The WARP country request is forced to `warp_N_out`. Therefore the observed
source is the final WARP address reached through that specific proxy, including
cases where a UAE proxy obtains a Finland WARP exit.

Country probes are lightweight JSON/text responses. They are not bandwidth
tests and do not consume the bandwidth budget. Existing bounded bandwidth probes
remain direct proxy quality signals in this phase; they do not determine route
country and a bandwidth failure cannot mark a proxy dead.

The WARP country stage shares the existing global proxy concurrency limit and
request timeout. It does not create an unbounded goroutine or response cache.
Only one primary WARP geo request is made per active proxy per refresh; the
fallback witness is used only after primary failure.

### Adaptive WARP-only reprobe

`COUNTRY_REPROBE_INTERVAL` schedules a separate retry for published,
WARP-healthy profiles whose WARP route evidence is unavailable or conflicting.
It starts Xray only for those profiles and makes the exact `warp_N_out`
country request using the normal witness order. It does not fetch sources,
resolve DNS, run direct-health samples, or consume the bandwidth budget. A
successful state change atomically rebuilds the cached country snapshot while
preserving the original refresh timestamp; refresh and reprobe are serialized to
keep runtime and publication state coherent.

## 7. Typed immutable publication snapshot

The atomic cache must retain the ordered typed entries used to build output:

```go
type CachedEntry struct {
    Entry     rename.RenamedEntry
    Countries country.RouteCountries
}

type CachedData struct {
    Entries     []CachedEntry
    Metadata    format.FormatMetadata
    Output      string
    JSONOutput  []byte
    LastRefresh time.Time
}
```

`Cached()` deep-copies records, query maps, country data, and byte slices. The
handler never reads mutable runtime state. Default URL and JSON bodies remain
precomputed fast paths; personalized views filter the typed snapshot and render
a temporary response.

## 8. WARP-aware JSON formatting

The existing formatter remains a compatibility wrapper:

```go
func FormatXrayJSON(entries []rename.RenamedEntry, meta FormatMetadata) []byte
```

It calls a new option-aware function with WARP enabled. With WARP enabled each
config remains:

```text
proxy-N, warp-out-N, direct, block
catch-all -> warp-out-N
```

With WARP disabled it becomes:

```text
proxy-N, direct, block
catch-all -> proxy-N
```

The proxy outbound remains first for v2rayNG detection. Existing routing blocks
and direct exceptions remain unchanged. xHTTP and all currently supported
transport mappings must not regress.

### Complete xHTTP preservation

xHTTP support is end-to-end rather than formatter-only:

```text
upstream URL or xray JSON
  -> ProxyRecord query parameters
  -> in-process probe outbound
  -> URL subscription
  -> generated xray JSON (WARP on or off)
```

The official XHTTP share-link contract keeps `type=xhttp`, `host`, `path`, and
`mode` as ordinary editable parameters. Every other `xhttpSettings` field is
serialized without loss into the `extra` JSON object. This includes current
xray-core fields such as headers, range settings, XMUX, download settings,
padding, request placement, session/sequence settings, and fields introduced by
newer producers that this service does not yet know by name.

One shared codec must build and extract xHTTP settings for fetch conversion,
probing, and output formatting. `extra` must be a valid JSON object; malformed
input is rejected before probing. Xray's precedence is preserved: `extra` is
expanded first, then explicit `host`, `path`, and `mode` override it.

## 9. Failure and publication semantics

- A total failure of direct reachability probing preserves the old cache.
- Failure of WARP country probing does not mark a direct proxy DEAD.
- A refresh may publish entries with unresolved WARP country; unfiltered JSON
  remains available, while an `exclude` WARP view fails closed for those entries.
- A request producing zero entries returns a valid empty URL body or JSON array
  with `200`.
- Personalized responses never replace the atomic global cache.
- Existing stale source fallback and empty-publication guard remain authoritative.

## 10. Security and privacy

- Query errors echo only the invalid public parameter, never configured URLs or
  credentials.
- Headers contain aggregate counts only.
- Country probes cap response bodies and require `200`.
- Source URLs remain redacted in logs.
- WARP credentials have one internal source of truth shared by formatter and
  probe configuration.
- No public endpoint returns observed egress IPs.

## 11. Verification contract

Automated checks:

```bash
go test ./... -race -count=1
go vet ./...
CGO_ENABLED=0 go build -ldflags='-s -w' -o /tmp/vless-sub-server ./cmd/vless-sub-server
```

Measured local checks use the supplied environment without printing secrets:

- default URL and default JSON counts;
- JSON with `warp=off` and `warp=on`;
- direct and WARP country exclusion;
- aggregate headers and valid empty filtered output;
- refresh duration and country unknown/conflict totals;
- no xHTTP count regression;
- xHTTP `extra` round-trip with XMUX, ranges, download settings, and unknown
  future fields;
- at least several WARP profiles validated by a request through the generated
  `proxy -> WARP` chain.

The measured cold-start reference run published 205 routes in
`2m31.366154108s`. Exact-chain country was known for 127 direct routes and 167
WARP routes; 78 direct and 38 WARP observations remained unavailable. These are
honest witness failures, not countries inferred from ASN/RIR/server location.
Confirmed runtime values survive later transient provider failures, so repeated
successful refreshes can improve steady-state coverage without fabricating
certainty. With `exclude`, the unresolved routes fail closed.

## 12. Research basis

- Cloudflare WARP geo-exit and country tagging:
  <https://blog.cloudflare.com/geoexit-improving-warp-user-experience-larger-network/>
- Cloudflare anycast IP location model:
  <https://blog.cloudflare.com/cloudflare-servers-dont-own-ips-anymore/>
- Cloudflare egress IPv4/IPv6 semantics:
  <https://developers.cloudflare.com/cloudflare-one/traffic-policies/egress-policies/dedicated-egress-ips/>
- RFC 8805 geofeed format: <https://datatracker.ietf.org/doc/html/rfc8805>
- RFC 9632 geofeed discovery: <https://www.rfc-editor.org/rfc/rfc9632.html>
- MaxMind accuracy limitations:
  <https://support.maxmind.com/knowledge-base/articles/maxmind-geolocation-accuracy>
