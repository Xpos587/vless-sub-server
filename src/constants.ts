// f/vless/constants.ts

import type { ParserConfig } from "./types";

export const SUBSCRIPTION_URLS: string[] = [
  "https://nya.astracat.ru/krQYNf60nkoe-43K",
  "https://sub.volnalink.uk/W5VYy08Uu9T30aTE",
];

export const CUSTOM_HEADERS: Record<string, string> = {
  "User-Agent": "Happ/1.4.9/Linux",
  "X-App-Version": "1.4.9",
  "X-Device-Locale": "EN",
  "X-Device-Os": "Linux",
  "X-Device-Model": "m7600qe_x86_64",
  "X-Hwid": "cb46d5c2545131323baa5a7d67cb05c6",
  "X-Ver-Os": "artix_unknown",
  "Accept-Language": "en,*",
  "Accept-Encoding": "identity",
};

export const PLACEHOLDER_HOSTS = new Set([
  "example.com",
  "example.org",
  "0.0.0.0",
  "127.0.0.1",
  "localhost",
  "::1",
]);

export const PROXY_SCHEMES = ["vless://", "vmess://", "trojan://", "ss://"] as const;

export const DEFAULT_CONFIG: ParserConfig = {
  subscriptionUrls: SUBSCRIPTION_URLS,
  customHeaders: CUSTOM_HEADERS,
  nameInclude: "",
  nameExclude: "",
  tcpTimeoutMs: 3000,
  dnsTimeoutMs: 2000,
  geoIpTimeoutMs: 7000,
  fetchTimeoutMs: 8000,
  maxConcurrentProbes: 20,
  maxConcurrentDns: 20,
};

export const IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,message,query,countryCode,city,isp";

export const IP_API_FIELDS = "status,message,query,countryCode,city,isp";
