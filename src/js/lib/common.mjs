/**
 * OSINT-X · lib/common.mjs
 * Shared helpers: output contract, timestamps, HTTP with timeout.
 * Node 18+, zero dependencies. Public information only.
 */

export const USER_AGENT = "OSINT-X/1.0 (+passive-osint; public-info-only)";
export const DEFAULT_TIMEOUT_MS = 10_000;

/** Current timestamp in ISO-8601 (UTC). */
export function nowIso() {
  return new Date().toISOString();
}

/**
 * Build an OSINT-X result following the output contract:
 * { status, target, data, sources, retrieved_at, errors }
 * status: "success" | "partial" | "error"
 */
export function makeResult(target, { data = {}, sources = [], errors = [] } = {}) {
  const status = errors.length === 0 ? "success" : Object.keys(data).length > 0 ? "partial" : "error";
  return { status, target, data, sources, retrieved_at: nowIso(), errors };
}

/** Push a string error onto an errors array (safe helper). */
export function pushError(errors, err) {
  errors.push(err instanceof Error ? err.message : String(err));
  return errors;
}

function withTimeout(signal, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error(`timeout after ${ms}ms`)), ms);
  const onAbort = () => {
    clearTimeout(timer);
    if (signal) signal.removeEventListener?.("abort", onAbort);
  };
  signal?.addEventListener?.("abort", onAbort, { once: true });
  return {
    signal: signal
      ? mergeSignals(signal, ctrl.signal)
      : ctrl.signal,
    done() {
      clearTimeout(timer);
    },
  };
}

// Combine an external AbortSignal with our internal one (both can abort).
function mergeSignals(a, b) {
  const ctrl = new AbortController();
  const fire = (e) => ctrl.abort(e?.target?.reason);
  a.addEventListener("abort", fire, { once: true });
  b.addEventListener("abort", fire, { once: true });
  return ctrl.signal;
}

/**
 * GET over fetch with a 10s default timeout and a fixed User-Agent.
 * Returns { status, headers, url, bodyText } — never throws for HTTP
 * error statuses; throws only on network/timeout errors.
 */
export async function httpGet(url, { timeoutMs = DEFAULT_TIMEOUT_MS, headers = {}, signal } = {}) {
  const t = withTimeout(signal, timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: t.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "*/*", ...headers },
    });
    const bodyText = await res.text();
    const outHeaders = {};
    for (const [k, v] of res.headers) outHeaders[k.toLowerCase()] = v;
    return { status: res.status, ok: res.ok, headers: outHeaders, url: res.url || url, bodyText };
  } catch (err) {
    throw new Error(`GET ${url} failed: ${err?.message ?? err}`);
  } finally {
    t.done();
  }
}

/**
 * HEAD over fetch with timeout. Falls back gracefully (caller decides
 * whether to retry with GET). Returns { status, headers, url }.
 */
export async function httpHead(url, { timeoutMs = DEFAULT_TIMEOUT_MS, headers = {}, signal } = {}) {
  const t = withTimeout(signal, timeoutMs);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      redirect: "follow",
      signal: t.signal,
      headers: { "User-Agent": USER_AGENT, ...headers },
    });
    const outHeaders = {};
    for (const [k, v] of res.headers) outHeaders[k.toLowerCase()] = v;
    return { status: res.status, ok: res.ok, headers: outHeaders, url: res.url || url };
  } catch (err) {
    throw new Error(`HEAD ${url} failed: ${err?.message ?? err}`);
  } finally {
    t.done();
  }
}

/** GET + JSON.parse with content-type-agnostic handling. */
export async function httpGetJson(url, opts = {}) {
  const res = await httpGet(url, { ...opts, headers: { Accept: "application/json", ...(opts.headers ?? {}) } });
  try {
    return { ...res, json: JSON.parse(res.bodyText) };
  } catch {
    throw new Error(`GET ${url} did not return valid JSON (HTTP ${res.status})`);
  }
}

/** Normalize a domain: strip scheme/path/port, lowercase, trim trailing dot. */
export function normalizeDomain(input) {
  if (typeof input !== "string" || !input.trim()) throw new Error("domain is required");
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, "").split("/")[0].split("?")[0].split("#")[0];
  d = d.split("@").pop().split(":")[0].replace(/\.$/, "");
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(d)) {
    throw new Error(`invalid domain: ${JSON.stringify(input)}`);
  }
  return d;
}

/** Basic IPv4/IPv6 validation (no DNS lookups). */
export function isIp(s) {
  if (typeof s !== "string") return false;
  const v4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
  const v6 = /^[0-9a-f:]+$/i.test(s) && s.includes(":");
  return v4.test(s) || v6;
}

/** Pretty-print a result to stdout. */
export function printResult(result) {
  console.log(JSON.stringify(result, null, 2));
}
