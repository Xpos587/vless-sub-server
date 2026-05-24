// f/vless/geoip.ts

import type { GeoInfo } from "./types";
import { IP_API_BATCH_URL } from "./constants";

export async function batchGeoLookup(ips: string[], timeoutMs: number): Promise<Map<string, GeoInfo>> {
  const map = new Map<string, GeoInfo>();

  if (ips.length === 0) return map;

  try {
    const resp = await fetch(IP_API_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ips),
      signal: AbortSignal.timeout(timeoutMs),
    });

    // Check rate limit headers
    const rlRemaining = parseInt(resp.headers.get("X-Rl") ?? "15", 10);
    const rlTtl = parseInt(resp.headers.get("X-Ttl") ?? "60", 10);

    if (resp.status === 429) {
      // Rate limited — wait and retry once
      await Bun.sleep(rlTtl * 1000);
      return retryGeoLookup(ips, timeoutMs, map);
    }

    if (!resp.ok) {
      return map; // Fallback: no geo data
    }

    const entries = (await resp.json()) as Array<{
      status: string;
      message?: string;
      query: string;
      countryCode?: string;
      city?: string;
      isp?: string;
    }>;

    for (const entry of entries) {
      if (entry.status === "success" && entry.countryCode) {
        map.set(entry.query, {
          countryCode: entry.countryCode,
          city: entry.city ?? "",
          isp: entry.isp ?? "",
          ip: entry.query,
        });
      }
    }

    // Log rate limit info for debugging
    if (rlRemaining <= 1) {
      console.warn(`ip-api rate limit low: ${rlRemaining} remaining, resets in ${rlTtl}s`);
    }
  } catch (err) {
    console.warn("Geo-IP lookup failed:", err instanceof Error ? err.message : String(err));
    // Fallback: proceed without geo data
  }

  return map;
}

async function retryGeoLookup(
  ips: string[],
  timeoutMs: number,
  map: Map<string, GeoInfo>
): Promise<Map<string, GeoInfo>> {
  try {
    const resp = await fetch(IP_API_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ips),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) return map;

    const entries = (await resp.json()) as Array<{
      status: string;
      query: string;
      countryCode?: string;
      city?: string;
      isp?: string;
    }>;

    for (const entry of entries) {
      if (entry.status === "success" && entry.countryCode) {
        map.set(entry.query, {
          countryCode: entry.countryCode,
          city: entry.city ?? "",
          isp: entry.isp ?? "",
          ip: entry.query,
        });
      }
    }
  } catch {
    // Retry also failed — proceed without geo data
  }

  return map;
}