// f/vless/rename.ts

import type { ProxyRecord, GeoInfo, ProbeResult } from "./types";
import { countryCodeToFlag } from "./flag-map";

export interface RenamedEntry {
  record: ProxyRecord;
  renamedFragment: string;
}

export function renameAll(
  records: Array<{ record: ProxyRecord; geo: GeoInfo | null; isLan: boolean }>,
  probeResults: Map<string, ProbeResult>
): RenamedEntry[] {
  const nameCounts = new Map<string, number>();
  const entries: RenamedEntry[] = [];

  for (const { record, geo, isLan } of records) {
    const key = `${record.host}:${record.port}`;
    const probe = probeResults.get(key);
    if (!probe || !probe.reachable) continue; // Skip dead servers

    const baseName = buildName(record, geo, isLan);

    // Name dedup with suffix
    const count = nameCounts.get(baseName) ?? 0;
    nameCounts.set(baseName, count + 1);
    const finalName = count === 0 ? baseName : `${baseName} (${count + 1})`;

    entries.push({ record, renamedFragment: finalName });
  }

  return entries;
}

function buildName(record: ProxyRecord, geo: GeoInfo | null, isLan: boolean): string {
  if (isLan) {
    return `${countryCodeToFlag("LAN")} LAN ${record.host}`;
  }

  if (!geo) {
    // Fallback: use original fragment or host
    return record.fragment || record.host;
  }

  const flag = countryCodeToFlag(geo.countryCode);
  const city = geo.city || geo.countryCode;
  const isp = geo.isp || "Unknown";

  return `${flag} ${city} (${isp})`;
}