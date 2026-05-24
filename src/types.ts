// f/vless/types.ts

export interface ProxyRecord {
  protocol: "vless" | "vmess" | "trojan" | "ss";
  host: string;
  port: number;
  uuidOrPassword: string;
  queryParams: Record<string, string>;
  fragment: string;
  originalLine: string;
}

export interface GeoInfo {
  countryCode: string;
  city: string;
  isp: string;
  ip: string;
}

export interface ProbeResult {
  reachable: boolean;
  latencyMs: number | null;
  failureType: "refused" | "timeout" | "error" | null;
}

export interface EnrichedProxy extends ProxyRecord {
  resolvedIp: string | null;
  geo: GeoInfo | null;
  probe: ProbeResult;
  renamedFragment: string;
}

export interface FetchResult {
  url: string;
  status: "ok" | "error";
  lines: string[];
  error?: string;
}

export interface ParserConfig {
  subscriptionUrls: string[];
  customHeaders: Record<string, string>;
  nameInclude: string;
  nameExclude: string;
  tcpTimeoutMs: number;
  dnsTimeoutMs: number;
  geoIpTimeoutMs: number;
  fetchTimeoutMs: number;
  maxConcurrentProbes: number;
  maxConcurrentDns: number;
}

export interface ParserResult {
  metadata: {
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
  };
  output: string;
}
