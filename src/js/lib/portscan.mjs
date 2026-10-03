/**
 * OSINT-X · 02 PORTSCAN
 * TCP connect scan with net.Socket. Authorized targets only.
 * No dependencies. Concurrency-limited, per-port timeout, banner grab.
 */
import net from "node:net";
import { makeResult } from "./common.mjs";

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
  1723, 3306, 3389, 5900, 8080, 8443,
];

const SERVICE_GUESS = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
  80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
  143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
  1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-proxy",
  8443: "https-alt",
};

const CONNECT_TIMEOUT_MS = 3000;
const BANNER_WAIT_MS = 1500;
const CONCURRENCY = 20;

function checkPort(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* noop */ }
      resolve(result);
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.on("data", (chunk) => { banner += chunk.toString("utf8", 0, 512); });
    socket.on("timeout", () => finish({ port, state: "filtered", service_guess: SERVICE_GUESS[port] ?? null, banner: null }));
    socket.on("error", (err) => {
      const code = err?.code ?? "";
      if (code === "ECONNREFUSED") finish({ port, state: "closed", service_guess: SERVICE_GUESS[port] ?? null, banner: null });
      else finish({ port, state: "filtered", service_guess: SERVICE_GUESS[port] ?? null, banner: null, error: code || String(err?.message ?? err) });
    });
    socket.connect(port, host, () => {
      // Connected: wait briefly for an optional banner, then report open.
      setTimeout(() => {
        finish({
          port,
          state: "open",
          service_guess: SERVICE_GUESS[port] ?? null,
          banner: banner.trim() ? banner.trim().slice(0, 512) : null,
        });
      }, BANNER_WAIT_MS);
    });
  });
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

function parsePorts(input) {
  if (input == null || input === "") return [...COMMON_PORTS];
  if (Array.isArray(input)) return input.map(Number).filter((n) => n >= 1 && n <= 65535);
  const out = new Set();
  for (const part of String(input).split(",")) {
    const p = part.trim();
    if (/^\d+-\d+$/.test(p)) {
      const [a, b] = p.split("-").map(Number);
      for (let i = Math.max(1, a); i <= Math.min(65535, b); i++) out.add(i);
    } else if (/^\d+$/.test(p)) {
      const n = Number(p);
      if (n >= 1 && n <= 65535) out.add(n);
    } else {
      throw new Error(`invalid port spec: ${JSON.stringify(p)} (use 80,443 or 1-1024)`);
    }
  }
  if (out.size === 0) throw new Error("no valid ports given");
  if (out.size > 1024) throw new Error("refusing to scan more than 1024 ports at once");
  return [...out].sort((x, y) => x - y);
}

/**
 * Scan TCP ports on an explicitly authorized host.
 * @param {string} host hostname or IP
 * @param {string|number[]|null} ports "80,443" | "1-1024" | [80,443] | null(defaults)
 */
export async function scanPorts(host, ports = null) {
  const errors = [];
  if (typeof host !== "string" || !host.trim()) {
    return makeResult(String(host ?? ""), { errors: ["host is required"] });
  }
  const target = host.trim();
  let list;
  try {
    list = parsePorts(ports);
  } catch (err) {
    return makeResult(target, { errors: [err.message] });
  }
  const sources = [`tcp:connect:${target}`];
  const results = await mapLimit(list, CONCURRENCY, (port) => checkPort(target, port));
  const open = results.filter((r) => r.state === "open");
  return makeResult(target, {
    data: {
      host: target,
      scanned: list,
      open,
      closed_or_filtered: results.filter((r) => r.state !== "open"),
      service_note: "service_guess is a port-number heuristic (inference), not a verified version scan.",
      consent_note: "Scan only hosts you own or are explicitly authorized to test.",
    },
    sources,
    errors,
  });
}
