/**
 * OSINT-X · 01 DOMAIN
 * DNS (dns/promises) + DoH fallback (Cloudflare) + RDAP.
 * Public information only. Explicit errors, per-query timeouts.
 */
import dns from "node:dns/promises";
import { httpGetJson, makeResult, normalizeDomain, pushError } from "./common.mjs";

const DOH = "https://cloudflare-dns.com/dns-query";
const RDAP_URL = (d) => `https://rdap.org/domain/${encodeURIComponent(d)}`;
const DOH_TIMEOUT = 10_000;
const DNS_TIMEOUT = 8_000;

async function resolveWithTimeout(fn, type, domain) {
  return await Promise.race([
    fn(type, domain).catch((err) => {
      throw err;
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`${type} lookup timed out`)), DNS_TIMEOUT)),
  ]);
}

async function tryResolve(resolver, type, domain, errors) {
  try {
    const records = await resolveWithTimeout(resolver.resolve.bind(resolver), type, domain);
    return records ?? [];
  } catch (err) {
    pushError(errors, `DNS ${type}: ${err?.message ?? err}`);
    return null;
  }
}

/** DoH fallback for record types Cloudflare dns-json supports. */
async function dohQuery(name, type, errors, sources) {
  try {
    const url = `${DOH}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const { json } = await httpGetJson(url, {
      timeoutMs: DOH_TIMEOUT,
      headers: { Accept: "application/dns-json" },
    });
    sources.push(`doh:cloudflare:${type}`);
    return (json?.Answer ?? []).map((a) => a.data);
  } catch (err) {
    pushError(errors, `DoH ${type}: ${err?.message ?? err}`);
    return null;
  }
}

async function fetchRdap(domain, errors, sources) {
  try {
    const { json, status } = await httpGetJson(RDAP_URL(domain), { timeoutMs: DOH_TIMEOUT });
    sources.push(`rdap:${RDAP_URL(domain)}`);
    if (status === 404) return { note: "no RDAP record (404)", observed: null };
    return {
      ldhName: json?.ldhName ?? null,
      handle: json?.handle ?? null,
      status: json?.status ?? null,
      registrar: (json?.entities ?? []).map((e) => e?.vcardArray?.[1]?.find?.((f) => f?.[0] === "fn")?.[3] ?? e?.handle ?? null).filter(Boolean),
      nameservers: (json?.nameservers ?? []).map((n) => n?.ldhName ?? null).filter(Boolean),
      events: (json?.events ?? []).map((e) => ({ action: e?.eventAction ?? null, date: e?.eventDate ?? null })),
      observed: true,
    };
  } catch (err) {
    pushError(errors, `RDAP: ${err?.message ?? err}`);
    return null;
  }
}

export async function investigateDomain(rawInput) {
  const errors = [];
  const sources = [];
  let domain;
  try {
    domain = normalizeDomain(rawInput);
  } catch (err) {
    return makeResult(String(rawInput ?? ""), { errors: [err.message] });
  }

  const resolver = new dns.Resolver({ timeout: DNS_TIMEOUT, tries: 2 });
  const data = { domain };

  const [a, aaaa, mx, txt, ns] = await Promise.all([
    tryResolve(resolver, "A", domain, errors),
    tryResolve(resolver, "AAAA", domain, errors),
    tryResolve(resolver, "MX", domain, errors),
    tryResolve(resolver, "TXT", domain, errors),
    tryResolve(resolver, "NS", domain, errors),
  ]);
  sources.push("dns:system-resolver");
  data.records = { A: a, AAAA: aaaa, MX: mx, TXT: txt, NS: ns };

  // DoH fallback only for record types missing locally (A/AAAA/TXT).
  for (const type of ["A", "AAAA", "TXT"]) {
    if (data.records[type] === null) {
      const doh = await dohQuery(domain, type, errors, sources);
      if (doh) data.records[type] = { observed_via: "doh-cloudflare", answers: doh };
    }
  }

  data.rdap = await fetchRdap(domain, errors, sources);
  data.note =
    "Passive lookup only: DNS + RDAP public records. WHOIS legacy port-43 is intentionally not used.";

  return makeResult(domain, { data, sources, errors });
}
