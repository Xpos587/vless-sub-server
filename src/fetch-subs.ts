// f/vless/fetch-subs.ts

import type { FetchResult, ParserConfig } from "./types";
import { PROXY_SCHEMES } from "./constants";

export async function fetchSubscriptions(config: ParserConfig): Promise<FetchResult[]> {
  const results = await Promise.allSettled(
    config.subscriptionUrls.map((url) => fetchSingleSubscription(url, config))
  );

  return results.map((result, i) => {
    if (result.status === "fulfilled") {
      return result.value;
    }
    return {
      url: config.subscriptionUrls[i],
      status: "error" as const,
      lines: [],
      error: result.reason instanceof Error ? result.reason.message : "Unknown error",
    };
  });
}

async function fetchSingleSubscription(url: string, config: ParserConfig): Promise<FetchResult> {
  try {
    const response = await fetch(url, {
      headers: config.customHeaders,
      signal: AbortSignal.timeout(config.fetchTimeoutMs),
      redirect: "follow",
    });

    if (!response.ok) {
      return {
        url,
        status: "error",
        lines: [],
        error: `HTTP ${response.status}`,
      };
    }

    const rawBody = await response.text();
    const lines = decodeSubscription(rawBody);

    if (lines.length === 0) {
      return {
        url,
        status: "error",
        lines: [],
        error: "Empty response after decode",
      };
    }

    return { url, status: "ok", lines };
  } catch (err) {
    return {
      url,
      status: "error",
      lines: [],
      error: err instanceof Error ? err.message : "Unknown fetch error",
    };
  }
}

function decodeSubscription(rawBody: string): string[] {
  const trimmed = rawBody.trim();

  // Try sing-box / Xray JSON format first
  try {
    const parsed = JSON.parse(trimmed);
    const urls = extractSingboxUrls(parsed);
    if (urls.length > 0) return urls;
  } catch {
    // Not JSON
  }

  // Try base64 decode
  try {
    let normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4 !== 0) {
      normalized += "=";
    }
    const decoded = Buffer.from(normalized, "base64").toString("utf-8");

    // Decoded might be sing-box JSON
    try {
      const parsed = JSON.parse(decoded);
      const urls = extractSingboxUrls(parsed);
      if (urls.length > 0) return urls;
    } catch {}

    const decodedLines = decoded
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    if (decodedLines.some((l) => PROXY_SCHEMES.some((s) => l.startsWith(s)))) {
      return decodedLines;
    }
  } catch {
    // Not base64
  }

  // Raw text — split by newlines
  return trimmed
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function extractSingboxUrls(data: unknown): string[] {
  const urls: string[] = [];
  const items = Array.isArray(data) ? data : [data];

  for (const item of items) {
    if (typeof item !== "object" || item === null) continue;
    const outbounds: unknown[] = (item as any).outbounds ?? [];
    const remarks: string = (item as any).remarks ?? "";

    for (const ob of outbounds) {
      if (typeof ob !== "object" || ob === null) continue;
      const proto = (ob as any).protocol ?? "";
      if (!["vless", "vmess", "trojan", "shadowsocks"].includes(proto)) continue;

      const tag = (ob as any).tag ?? "";
      const settings = (ob as any).settings ?? {};
      const stream = (ob as any).streamSettings ?? {};

      const url = singboxOutboundToUrl(proto, settings, stream, remarks || tag);
      if (url) urls.push(url);
    }
  }

  return urls;
}

function singboxOutboundToUrl(
  protocol: string,
  settings: Record<string, any>,
  stream: Record<string, any>,
  remark: string
): string | null {
  try {
    const net = stream.network ?? "tcp";
    const security = stream.security ?? "none";
    const fp = stream.realitySettings?.fingerprint ?? stream.tlsSettings?.fingerprint ?? "";
    const sni = stream.realitySettings?.serverName ?? stream.tlsSettings?.serverName ?? "";
    const pbk = stream.realitySettings?.publicKey ?? "";
    const sid = stream.realitySettings?.shortId ?? "";
    const flow = stream.realitySettings?.flow ?? "";

    if (protocol === "vless") {
      const vnext = settings.vnext ?? [];
      if (vnext.length === 0) return null;
      const server = vnext[0];
      const uuid = server.users?.[0]?.id ?? server.users?.[0]?.uuid ?? "";
      const port = server.port ?? 443;
      const address = server.address ?? "";

      const params = new URLSearchParams();
      if (net) params.set("type", net);
      if (security) params.set("security", security);
      if (fp) params.set("fp", fp);
      if (sni) params.set("sni", sni);
      if (pbk) params.set("pbk", pbk);
      if (sid) params.set("sid", sid);
      if (flow) params.set("flow", flow);

      if (stream.xhttpSettings) {
        params.set("path", stream.xhttpSettings.path ?? "/");
        if (stream.xhttpSettings.mode) params.set("mode", stream.xhttpSettings.mode);
        if (stream.xhttpSettings.host) params.set("host", stream.xhttpSettings.host);
      }
      if (stream.wsSettings) {
        params.set("path", stream.wsSettings.path ?? "/");
        if (stream.wsSettings.headers?.Host) params.set("host", stream.wsSettings.headers.Host);
      }
      if (stream.grpcSettings) {
        if (stream.grpcSettings.serviceName) params.set("serviceName", stream.grpcSettings.serviceName);
        if (stream.grpcSettings.mode) params.set("mode", stream.grpcSettings.mode);
      }
      if (stream.tcpSettings?.header?.type === "http") {
        params.set("headerType", "http");
      }

      const frag = remark ? `#${encodeURIComponent(remark)}` : "";
      return `vless://${uuid}@${address}:${port}?${params.toString()}${frag}`;
    }

    if (protocol === "vmess") {
      const vnext = settings.vnext ?? [];
      if (vnext.length === 0) return null;
      const server = vnext[0];
      const uuid = server.users?.[0]?.id ?? "";
      const alterId = server.users?.[0]?.alterId ?? 0;
      const port = server.port ?? 443;
      const address = server.address ?? "";

      const config: Record<string, unknown> = {
        v: "2", ps: remark, add: address, port, id: uuid, aid: alterId,
        net, type: net, tls: security === "tls" || security === "reality" ? "tls" : "",
        sni, path: stream.wsSettings?.path ?? stream.xhttpSettings?.path ?? "/",
        host: stream.wsSettings?.headers?.Host ?? stream.xhttpSettings?.host ?? "",
      };
      const json = JSON.stringify(config);
      let encoded = Buffer.from(json).toString("base64").replace(/=+$/, "");
      return `vmess://${encoded}`;
    }

    if (protocol === "trojan") {
      const servers = settings.servers ?? [];
      if (servers.length === 0) return null;
      const server = servers[0];
      const password = server.password ?? "";
      const port = server.port ?? 443;
      const address = server.address ?? "";

      const params = new URLSearchParams();
      if (security) params.set("security", security);
      if (sni) params.set("sni", sni);
      if (fp) params.set("fp", fp);
      if (net !== "tcp") params.set("type", net);
      if (stream.wsSettings?.path) params.set("path", stream.wsSettings.path);

      const frag = remark ? `#${encodeURIComponent(remark)}` : "";
      return `trojan://${password}@${address}:${port}?${params.toString()}${frag}`;
    }

    if (protocol === "shadowsocks") {
      const servers = settings.servers ?? [];
      if (servers.length === 0) return null;
      const server = servers[0];
      const method = server.method ?? "aes-256-gcm";
      const password = server.password ?? "";
      const port = server.port ?? 443;
      const address = server.address ?? "";

      const userInfo = Buffer.from(`${method}:${password}`).toString("base64url");
      const frag = remark ? `#${encodeURIComponent(remark)}` : "";
      return `ss://${userInfo}@${address}:${port}${frag}`;
    }
  } catch {
    return null;
  }

  return null;
}
