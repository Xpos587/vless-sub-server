import { fetchSubscriptions } from "./fetch-subs";
import { parseAllLines, applyNameFilter } from "./parse";
import { resolveHosts } from "./dns";
import { tcpProbeAll } from "./probe";
import { renameAll } from "./rename";
import { formatOutput } from "./format";
import { SUBSCRIPTION_URLS, CUSTOM_HEADERS } from "./constants";
import type { ProxyRecord, GeoInfo, ProbeResult } from "./types";

const PORT = parseInt(process.env.PORT ?? "8080", 10);
const REFRESH_INTERVAL_MS = parseInt(process.env.REFRESH_INTERVAL_MS ?? "1800000", 10);
const NAME_INCLUDE = process.env.NAME_INCLUDE ?? "";
const NAME_EXCLUDE = process.env.NAME_EXCLUDE ?? "";

let cachedOutput: string | null = null;
let lastRefresh = 0;
let refreshing = false;

async function refreshSubscriptions(): Promise<string> {
  const fetchResults = await fetchSubscriptions({
    subscriptionUrls: SUBSCRIPTION_URLS,
    customHeaders: CUSTOM_HEADERS,
    nameInclude: NAME_INCLUDE,
    nameExclude: NAME_EXCLUDE,
    fetchTimeoutMs: 8000,
  } as any);

  const sourcesOk = fetchResults.filter((r) => r.status === "ok").length;
  const sourcesFailed = fetchResults.filter((r) => r.status === "error").length;

  const allLines = fetchResults.flatMap((r) => r.lines);
  const { records, skipped, duplicates } = parseAllLines(allLines);
  const filtered = applyNameFilter(records, NAME_INCLUDE, NAMEExclude);

  // DNS
  const uniqueHosts = [...new Set(filtered.map((r) => r.host))];
  const dnsMap = await resolveHosts(uniqueHosts, 20, 2000);
  const withDns = filtered.filter((r) => {
    const dns = dnsMap.get(r.host);
    return dns && dns.ip !== null;
  });

  // TCP probes
  const probeHosts = withDns.map((r) => ({
    host: r.host,
    port: r.port,
    ip: dnsMap.get(r.host)?.ip ?? null,
  }));
  const probeResults = await tcpProbeAll(probeHosts, 20, 3000);

  // TODO: Exit-IP probe phase (Xray gRPC + ipwho.is)
  // For now: use DNS IP for geo (same as before)
  const aliveRecords = withDns.map((r) => ({
    record: r,
    geo: null as GeoInfo | null,
    isLan: dnsMap.get(r.host)?.isPrivate ?? false,
  }));

  const renamed = renameAll(aliveRecords, probeResults);

  const totalAlive = renamed.length;
  const totalDead = withDns.length - totalAlive;

  return formatOutput(renamed, {
    totalFetched: allLines.length,
    totalParsed: filtered.length,
    totalSkipped: skipped,
    totalDuplicates: duplicates,
    totalAlive,
    totalDead,
    sourcesOk,
    sourcesFailed,
    geoAvailable: 0,
    geoTotal: withDns.length,
  });
}

async function tryRefresh(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  try {
    cachedOutput = await refreshSubscriptions();
    lastRefresh = Date.now();
    console.log(`[refresh] done at ${new Date().toISOString()}`);
  } catch (err) {
    console.error(`[refresh] failed:`, err instanceof Error ? err.message : err);
  } finally {
    refreshing = false;
  }
}

// HTTP server
const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/sub" || url.pathname === "/") {
      if (!cachedOutput) await tryRefresh();
      return new Response(cachedOutput ?? "# No data yet\n", {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-cache",
          "X-Last-Refresh": new Date(lastRefresh).toISOString(),
        },
      });
    }

    if (url.pathname === "/health") {
      return new Response("ok", { headers: { "Content-Type": "text/plain" } });
    }

    return new Response("not found", { status: 404 });
  },
});

console.log(`[server] listening on :${PORT}`);
console.log(`[server] refresh interval: ${REFRESH_INTERVAL_MS / 1000}s`);

// Initial refresh
tryRefresh();

// Periodic refresh
setInterval(() => tryRefresh(), REFRESH_INTERVAL_MS);