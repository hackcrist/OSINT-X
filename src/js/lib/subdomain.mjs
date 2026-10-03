/**
 * OSINT-X · 03 SUBDOMAIN
 * Passive enumeration via Certificate Transparency (crt.sh) + optional
 * DNS confirmation + tiny built-in wordlist. Public info only.
 */
import dns from "node:dns/promises";
import { httpGet, makeResult, normalizeDomain, pushError } from "./common.mjs";

const CRT_URL = (d) => `https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`;
const WORDLIST = ["www", "mail", "ftp", "webmail", "smtp", "blog", "shop", "api", "dev", "test", "staging", "vpn", "ns1", "ns2", "mx1", "portal", "secure", "admin", "cdn", "app"];

async function fetchCt(domain, errors, sources) {
  const { bodyText, status } = await httpGet(CRT_URL(domain), {
    timeoutMs: 10_000,
    headers: { Accept: "application/json" },
  });
  sources.push(`ct:crt.sh:${domain}`);
  if (status !== 200) throw new Error(`crt.sh returned HTTP ${status}`);
  let rows;
  try {
    rows = JSON.parse(bodyText);
  } catch {
    throw new Error("crt.sh did not return valid JSON");
  }
  const names = new Set();
  for (const r of rows ?? []) {
    const field = String(r?.name_value ?? "");
    for (const line of field.split("\n")) {
      const n = line.trim().toLowerCase().replace(/^\*\./, "");
      if (n && (n === domain || n.endsWith(`.${domain}`))) names.add(n);
    }
  }
  return [...names].sort();
}

export async function enumerateSubdomains(rawDomain, { confirmDns = true, wordlist = true } = {}) {
  const errors = [];
  const sources = [];
  let domain;
  try {
    domain = normalizeDomain(rawDomain);
  } catch (err) {
    return makeResult(String(rawDomain ?? ""), { errors: [err.message] });
  }

  const found = new Set();
  try {
    for (const n of await fetchCt(domain, errors, sources)) found.add(n);
  } catch (err) {
    pushError(errors, `certificate-transparency: ${err?.message ?? err}`);
  }

  if (wordlist) {
    const resolver = new dns.Resolver({ timeout: 5000, tries: 1 });
    await Promise.all(
      WORDLIST.map(async (w) => {
        const candidate = `${w}.${domain}`;
        try {
          await resolver.resolve(candidate, "A");
          found.add(candidate);
          if (!sources.includes("dns:wordlist-probe")) sources.push("dns:wordlist-probe");
        } catch { /* absent — not an error */ }
      }),
    );
  }

  let confirmed = [...found].sort();
  if (confirmDns && confirmed.length > 0) {
    const resolver = new dns.Resolver({ timeout: 5000, tries: 1 });
    const checks = await Promise.all(
      confirmed.slice(0, 200).map(async (name) => {
        try {
          const a = await resolver.resolve(name, "A");
          return { name, resolves: true, A: a };
        } catch {
          return { name, resolves: false, A: null };
        }
      }),
    );
    sources.push("dns:confirmation");
    return makeResult(domain, {
      data: { domain, count: checks.length, subdomains: checks, truncated: confirmed.length > 200 },
      sources,
      errors,
    });
  }

  return makeResult(domain, {
    data: { domain, count: confirmed.length, subdomains: confirmed.map((name) => ({ name, resolves: null, A: null })) },
    sources,
    errors,
  });
}
