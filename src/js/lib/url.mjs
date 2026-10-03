/**
 * OSINT-X · 08 URL
 * Fetch headers + manual redirect chain (max 5) + TLS certificate info.
 * Public information only. Timeouts everywhere.
 */
import tls from "node:tls";
import { makeResult, pushError } from "./common.mjs";
import { USER_AGENT, DEFAULT_TIMEOUT_MS } from "./common.mjs";

const MAX_REDIRECTS = 5;

async function fetchOnce(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctrl.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "*/*" },
    });
    const headers = {};
    for (const [k, v] of res.headers) headers[k.toLowerCase()] = v;
    // Drain body so sockets don't leak; cap at ~64 KiB.
    let bodyBytes = 0;
    try {
      const buf = Buffer.from(await res.arrayBuffer());
      bodyBytes = buf.length;
    } catch { /* ignore body errors */ }
    return { status: res.status, headers, location: res.headers.get("location"), bodyBytes };
  } finally {
    clearTimeout(timer);
  }
}

function getTlsCert(hostname, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, timeout: timeoutMs, rejectUnauthorized: false },
      () => {
        try {
          const cert = socket.getPeerCertificate(true);
          socket.end();
          if (!cert || Object.keys(cert).length === 0) return resolve({ present: false, cert: null });
          resolve({
            present: true,
            cert: {
              subject: cert.subject ?? null,
              issuer: cert.issuer ?? null,
              valid_from: cert.valid_from ?? null,
              valid_to: cert.valid_to ?? null,
              fingerprint256: cert.fingerprint256 ?? null,
              san: cert.subjectaltname ?? null,
            },
          });
        } catch (err) {
          resolve({ present: false, cert: null, error: err?.message ?? String(err) });
        }
      },
    );
    socket.on("timeout", () => { socket.destroy(new Error("tls timeout")); });
    socket.on("error", (err) => resolve({ present: false, cert: null, error: err?.message ?? String(err) }));
  });
}

function inferTech(headers) {
  const hints = [];
  if (headers["server"]) hints.push({ tech: headers["server"], basis: "server header (observed)" });
  if (headers["x-powered-by"]) hints.push({ tech: headers["x-powered-by"], basis: "x-powered-by header (observed)" });
  if (headers["via"]) hints.push({ tech: headers["via"], basis: "via header (observed)" });
  return hints;
}

export async function investigateUrl(raw) {
  const input = String(raw ?? "").trim();
  const errors = [];
  const sources = [];
  let current;
  try {
    current = new URL(input);
  } catch {
    return makeResult(input, { errors: [`invalid URL: ${JSON.stringify(raw ?? "")}`] });
  }
  if (!["http:", "https:"].includes(current.protocol)) {
    return makeResult(input, { errors: [`unsupported scheme ${current.protocol} (http/https only)`] });
  }

  const chain = [];
  let final = null;
  try {
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      const step = await fetchOnce(current.toString(), DEFAULT_TIMEOUT_MS);
      chain.push({ url: current.toString(), status: step.status, location: step.location, headers: step.headers });
      sources.push(`http:${current.host}`);
      if ([301, 302, 303, 307, 308].includes(step.status) && step.location) {
        current = new URL(step.location, current);
        continue;
      }
      final = { ...step, url: current.toString() };
      break;
    }
    if (!final) pushError(errors, `too many redirects (>${MAX_REDIRECTS})`);
  } catch (err) {
    pushError(errors, `fetch: ${err?.message ?? err}`);
  }

  let certificate = null;
  try {
    const host = new URL(chain[chain.length - 1]?.url ?? input).hostname;
    const proto = new URL(chain[chain.length - 1]?.url ?? input).protocol;
    if (proto === "https:") certificate = await getTlsCert(host);
  } catch (err) {
    pushError(errors, `tls-cert: ${err?.message ?? err}`);
  }

  const lastHeaders = final?.headers ?? chain[chain.length - 1]?.headers ?? {};
  return makeResult(input, {
    data: {
      input,
      final_url: final?.url ?? null,
      final_status: final?.status ?? null,
      redirect_count: Math.max(0, chain.length - 1),
      redirect_chain: chain.map((c) => ({ url: c.url, status: c.status, location: c.location ?? null })),
      headers: lastHeaders,
      tech_hints: inferTech(lastHeaders),
      tls_certificate: certificate,
    },
    sources,
    errors,
  });
}
