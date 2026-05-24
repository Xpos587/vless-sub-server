// f/vless/parse.ts

import type { ProxyRecord } from "./types";
import { PROXY_SCHEMES, PLACEHOLDER_HOSTS } from "./constants";

export function parseAllLines(allLines: string[]): {
  records: ProxyRecord[];
  skipped: number;
  duplicates: number;
} {
  const seen = new Set<string>();
  const records: ProxyRecord[] = [];
  let skipped = 0;
  let duplicates = 0;

  for (const line of allLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      skipped++;
      continue;
    }

    if (!PROXY_SCHEMES.some((s) => trimmed.startsWith(s))) {
      skipped++;
      continue;
    }

    let record: ProxyRecord | null = null;

    if (trimmed.startsWith("vless://")) {
      record = parseVless(trimmed);
    } else if (trimmed.startsWith("vmess://")) {
      record = parseVmess(trimmed);
    } else if (trimmed.startsWith("trojan://")) {
      record = parseTrojan(trimmed);
    } else if (trimmed.startsWith("ss://")) {
      record = parseSs(trimmed);
    }

    if (!record) {
      skipped++;
      continue;
    }

    // Validate
    if (!record.host || record.port <= 0 || record.port > 65535) {
      skipped++;
      continue;
    }

    if (PLACEHOLDER_HOSTS.has(record.host)) {
      skipped++;
      continue;
    }

    // Dedup by (host, port, protocol)
    const dedupKey = `${record.host}:${record.port}:${record.protocol}`;
    if (seen.has(dedupKey)) {
      duplicates++;
      continue;
    }
    seen.add(dedupKey);

    records.push(record);
  }

  return { records, skipped, duplicates };
}

function parseVless(line: string): ProxyRecord | null {
  try {
    // Strip trailing garbage characters
    let cleaned = line.replace(/\\+$/, "").replace(/%22,%22/g, "").replace(/%22/g, "");
    // Fix double-escaped backslashes in query params
    cleaned = cleaned.replace(/\\\\+/g, "");

    const url = new URL(cleaned);
    const host = url.hostname;
    const port = parseInt(url.port, 10) || 443;
    const uuid = decodeURIComponent(url.username);
    const fragment = decodeURIComponent(url.hash.slice(1));
    const queryParams: Record<string, string> = {};
    url.searchParams.forEach((v, k) => {
      queryParams[k] = v;
    });

    // Normalize insecure flags
    const normalized = normalizeInsecure(queryParams);

    return {
      protocol: "vless",
      host,
      port,
      uuidOrPassword: uuid,
      queryParams: normalized,
      fragment,
      originalLine: line,
    };
  } catch {
    return null;
  }
}

function parseVmess(line: string): ProxyRecord | null {
  try {
    let encoded = line.slice("vmess://".length);
    // Normalize URL-safe base64
    encoded = encoded.replace(/-/g, "+").replace(/_/g, "/");
    while (encoded.length % 4 !== 0) {
      encoded += "=";
    }
    const decoded = Buffer.from(encoded, "base64").toString("utf-8");
    const config = JSON.parse(decoded);

    const host = config.add || config.address;
    const port = parseInt(config.port, 10);
    const uuid = config.id;
    const fragment = config.ps || "";

    const queryParams: Record<string, string> = {};
    if (config.net) queryParams.type = config.net;
    if (config.tls === "tls") queryParams.security = "tls";
    if (config.sni) queryParams.sni = config.sni;
    if (config.path) queryParams.path = config.path;
    if (config.host) queryParams.host = config.host;
    if (config.flow) queryParams.flow = config.flow;

    return {
      protocol: "vmess",
      host,
      port,
      uuidOrPassword: uuid,
      queryParams,
      fragment,
      originalLine: line,
    };
  } catch {
    return null;
  }
}

function parseTrojan(line: string): ProxyRecord | null {
  try {
    const url = new URL(line);
    const host = url.hostname;
    const port = parseInt(url.port, 10) || 443;
    const password = decodeURIComponent(url.username);
    const fragment = decodeURIComponent(url.hash.slice(1));
    const queryParams: Record<string, string> = {};
    url.searchParams.forEach((v, k) => {
      queryParams[k] = v;
    });

    const normalized = normalizeInsecure(queryParams);

    return {
      protocol: "trojan",
      host,
      port,
      uuidOrPassword: password,
      queryParams: normalized,
      fragment,
      originalLine: line,
    };
  } catch {
    return null;
  }
}

function parseSs(line: string): ProxyRecord | null {
  try {
    let encoded = line.slice("ss://".length);
    // ss://base64@host:port#fragment or ss://method:password@host:port#fragment
    const hashIdx = encoded.indexOf("#");
    let fragment = "";
    let main = encoded;
    if (hashIdx !== -1) {
      fragment = decodeURIComponent(encoded.slice(hashIdx + 1));
      main = encoded.slice(0, hashIdx);
    }

    // Try base64@host:port format
    const atIdx = main.lastIndexOf("@");
    if (atIdx === -1) {
      // Try full base64
      let b64 = main.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4 !== 0) b64 += "=";
      const decoded = Buffer.from(b64, "base64").toString("utf-8");
      const innerAt = decoded.indexOf("@");
      if (innerAt === -1) return null;
      const methodPassword = decoded.slice(0, innerAt);
      const hostPort = decoded.slice(innerAt + 1);
      const colonIdx = methodPassword.indexOf(":");
      const method = methodPassword.slice(0, colonIdx);
      const password = methodPassword.slice(colonIdx + 1);
      const lastColon = hostPort.lastIndexOf(":");
      const host = hostPort.slice(0, lastColon);
      const port = parseInt(hostPort.slice(lastColon + 1), 10);

      return {
        protocol: "ss",
        host,
        port,
        uuidOrPassword: password,
        queryParams: { method },
        fragment,
        originalLine: line,
      };
    }

    const methodPassword = main.slice(0, atIdx);
    const hostPort = main.slice(atIdx + 1);
    const colonIdx = methodPassword.indexOf(":");
    const method = methodPassword.slice(0, colonIdx);
    const password = methodPassword.slice(colonIdx + 1);
    const lastColon = hostPort.lastIndexOf(":");
    const host = hostPort.slice(0, lastColon);
    const port = parseInt(hostPort.slice(lastColon + 1), 10);

    return {
      protocol: "ss",
      host,
      port,
      uuidOrPassword: password,
      queryParams: { method },
      fragment,
      originalLine: line,
    };
  } catch {
    return null;
  }
}

function normalizeInsecure(params: Record<string, string>): Record<string, string> {
  const result = { ...params };
  if (result.allowInsecure || result.insecure || result.allow_insecure) {
    result.insecure = "1";
    delete result.allowInsecure;
    delete result.allow_insecure;
  }
  return result;
}

export function applyNameFilter(
  records: ProxyRecord[],
  nameInclude: string,
  nameExclude: string
): ProxyRecord[] {
  let filtered = records;
  if (nameExclude) {
    const re = new RegExp(nameExclude);
    filtered = filtered.filter((r) => !re.test(r.fragment));
  }
  if (nameInclude) {
    const re = new RegExp(nameInclude);
    filtered = filtered.filter((r) => re.test(r.fragment));
  }
  return filtered;
}