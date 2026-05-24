// f/vless/probe.ts

import type { ProbeResult } from "./types";
import { Semaphore } from "./semaphore";

export async function tcpProbeAll(
  hosts: Array<{ host: string; port: number; ip: string | null }>,
  maxConcurrent: number,
  timeoutMs: number
): Promise<Map<string, ProbeResult>> {
  const results = new Map<string, ProbeResult>();
  const sem = new Semaphore(maxConcurrent);

  await Promise.allSettled(
    hosts.map(async ({ host, port, ip }) => {
      await sem.acquire();
      try {
        const target = ip ?? host;
        const key = `${host}:${port}`;
        const start = performance.now();
        const result = await tcpProbe(target, port, timeoutMs);
        const latencyMs = result.reachable ? Math.round(performance.now() - start) : null;
        results.set(key, { ...result, latencyMs });
      } finally {
        sem.release();
      }
    })
  );

  return results;
}

function tcpProbe(hostname: string, port: number, timeoutMs: number): Promise<ProbeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const mark = (result: ProbeResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const timer = setTimeout(() => {
      mark({ reachable: false, latencyMs: null, failureType: "timeout" });
    }, timeoutMs);

    const socket = Bun.connect({
      hostname,
      port,
      socket: {
        data() {},
        open(socket) {
          clearTimeout(timer);
          mark({ reachable: true, latencyMs: null, failureType: null });
          socket.end();
        },
        connectError(_socket, error) {
          clearTimeout(timer);
          const msg = String(error);
          if (msg.includes("ECONNREFUSED")) {
            mark({ reachable: false, latencyMs: null, failureType: "refused" });
          } else {
            mark({ reachable: false, latencyMs: null, failureType: "error" });
          }
        },
        error(_socket, _error) {
          clearTimeout(timer);
          mark({ reachable: false, latencyMs: null, failureType: "error" });
        },
        close(_socket, _error) {
          clearTimeout(timer);
          if (!settled) {
            mark({ reachable: false, latencyMs: null, failureType: "error" });
          }
        },
        timeout(socket) {
          clearTimeout(timer);
          mark({ reachable: false, latencyMs: null, failureType: "timeout" });
          socket.end();
        },
        end() {
          clearTimeout(timer);
          if (!settled) {
            mark({ reachable: false, latencyMs: null, failureType: "error" });
          }
        },
      },
    });

    socket.catch(() => {
      clearTimeout(timer);
      mark({ reachable: false, latencyMs: null, failureType: "error" });
    });
  });
}