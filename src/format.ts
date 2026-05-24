// f/vless/format.ts

import type { ProxyRecord } from "./types";

export interface FormatMetadata {
  totalFetched: number;
  totalParsed: number;
  totalSkipped: number;
  totalDuplicates: number;
  totalAlive: number;
  totalDead: number;
  sourcesOk: number;
  sourcesFailed: number;
  geoAvailable: number;
  geoTotal: number;
}

export function formatOutput(
  entries: Array<{ record: ProxyRecord; renamedFragment: string }>,
  metadata: FormatMetadata
): string {
  const lines: string[] = [];

  const now = new Date();
  const moscowOffset = 3 * 60; // UTC+3
  const moscowTime = new Date(now.getTime() + moscowOffset * 60 * 1000);
  const dateStr =
    moscowTime.toISOString().replace("T", " / ").slice(0, 22) + " (Moscow)";

  lines.push("# profile-title: Proxy Subscription Parser");
  lines.push("# profile-update-interval: 1");
  lines.push(`# Date/Time: ${dateStr}`);
  lines.push(`# Количество: ${metadata.totalAlive}`);
  lines.push(
    `# Sources: ${metadata.sourcesOk} ok, ${metadata.sourcesFailed} failed`
  );
  lines.push(
    `# Parsed: ${metadata.totalParsed} valid, ${metadata.totalSkipped} skipped, ${metadata.totalDuplicates} duplicates`
  );
  const probedTotal = metadata.totalAlive + metadata.totalDead;
  lines.push(
    `# Probed: ${probedTotal} total, ${metadata.totalAlive} alive, ${metadata.totalDead} dead`
  );
  lines.push(
    `# Geo: available for ${metadata.geoAvailable}/${metadata.geoTotal}`
  );
  lines.push("---");

  for (const { record, renamedFragment } of entries) {
    lines.push(reconstructUrl(record, renamedFragment));
  }

  return lines.join("\n");
}

function reconstructUrl(record: ProxyRecord, fragment: string): string {
  switch (record.protocol) {
    case "vless":
      return reconstructVless(record, fragment);
    case "vmess":
      return reconstructVmess(record, fragment);
    case "trojan":
      return reconstructTrojan(record, fragment);
    case "ss":
      return reconstructSs(record, fragment);
    default:
      return record.originalLine;
  }
}

function reconstructVless(record: ProxyRecord, fragment: string): string {
  const params = new URLSearchParams(record.queryParams).toString();
  const paramStr = params ? `?${params}` : "";
  const fragStr = fragment ? `#${encodeURIComponent(fragment)}` : "";
  return `vless://${record.uuidOrPassword}@${record.host}:${record.port}${paramStr}${fragStr}`;
}

function reconstructVmess(record: ProxyRecord, fragment: string): string {
  const config: Record<string, unknown> = {
    v: "2",
    ps: fragment,
    add: record.host,
    port: record.port,
    id: record.uuidOrPassword,
    net: record.queryParams.type || "tcp",
    type: record.queryParams.type || "none",
    tls: record.queryParams.security === "tls" ? "tls" : "",
    sni: record.queryParams.sni || "",
    path: record.queryParams.path || "/",
    host: record.queryParams.host || "",
  };
  const json = JSON.stringify(config);
  let encoded = Buffer.from(json).toString("base64");
  // Remove padding for VMess
  encoded = encoded.replace(/=+$/, "");
  return `vmess://${encoded}`;
}

function reconstructTrojan(record: ProxyRecord, fragment: string): string {
  const params = new URLSearchParams(record.queryParams).toString();
  const paramStr = params ? `?${params}` : "";
  const fragStr = fragment ? `#${encodeURIComponent(fragment)}` : "";
  return `trojan://${record.uuidOrPassword}@${record.host}:${record.port}${paramStr}${fragStr}`;
}

function reconstructSs(record: ProxyRecord, fragment: string): string {
  const method = record.queryParams.method || "aes-256-gcm";
  const userInfo = Buffer.from(
    `${method}:${record.uuidOrPassword}`
  ).toString("base64url");
  const fragStr = fragment ? `#${encodeURIComponent(fragment)}` : "";
  return `ss://${userInfo}@${record.host}:${record.port}${fragStr}`;
}