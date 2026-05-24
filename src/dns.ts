// f/vless/dns.ts

import { dns } from "bun";
import { Semaphore } from "./semaphore";

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
];

const LOOPBACK_IPV6 = /^::1$/;
const LINK_LOCAL_IPV6 = /^fe80:/i;

export interface DnsResult {
  ip: string | null;
  isPrivate: boolean;
  failed: boolean;
}

export async function resolveHosts(
  hosts: string[],
  maxConcurrent: number,
  timeoutMs: number
): Promise<Map<string, DnsResult>> {
  const results = new Map<string, DnsResult>();
  const sem = new Semaphore(maxConcurrent);
  const uniqueHosts = [...new Set(hosts)];

  await Promise.allSettled(
    uniqueHosts.map(async (host) => {
      // Skip if already an IP address
      if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":")) {
        const isPrivate = isPrivateIp(host);
        results.set(host, { ip: host, isPrivate, failed: false });
        return;
      }

      await sem.acquire();
      try {
        const ip = await resolveWithRetry(host, timeoutMs);
        if (ip) {
          const isPrivate = isPrivateIp(ip);
          results.set(host, { ip, isPrivate, failed: false });
        } else {
          results.set(host, { ip: null, isPrivate: false, failed: true });
        }
      } finally {
        sem.release();
      }
    })
  );

  return results;
}

async function resolveWithRetry(hostname: string, timeoutMs: number): Promise<string | null> {
  try {
    const result = await Promise.race([
      dns.lookup(hostname),
      Bun.sleep(timeoutMs).then(() => null),
    ]);
    if (result && result.length > 0) {
      const ip = result[0].address;
      // Validate not loopback/link-local
      if (LOOPBACK_IPV6.test(ip) || LINK_LOCAL_IPV6.test(ip)) {
        return null;
      }
      return ip;
    }
  } catch {
    // First attempt failed, retry once
  }

  // Single retry after 1 second
  try {
    await Bun.sleep(1000);
    const result = await Promise.race([
      dns.lookup(hostname),
      Bun.sleep(timeoutMs).then(() => null),
    ]);
    if (result && result.length > 0) {
      return result[0].address;
    }
  } catch {
    // Retry also failed
  }

  return null;
}

function isPrivateIp(ip: string): boolean {
  for (const range of PRIVATE_RANGES) {
    if (range.test(ip)) return true;
  }
  if (LOOPBACK_IPV6.test(ip)) return true;
  return false;
}