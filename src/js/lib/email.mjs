/**
 * OSINT-X · 07 EMAIL
 * Allowed checks only: address syntax, domain MX/TXT/SPF/DMARC via DNS.
 * No breach databases, no login attempts, no verification probes.
 */
import dns from "node:dns/promises";
import { makeResult, pushError } from "./common.mjs";

const DISPOSABLE = new Set([
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
  "throwawaymail.com", "yopmail.com", "trashmail.com",
]);

const FREEMAIL = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
  "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com",
]);

async function tryResolve(resolver, type, name, errors) {
  try {
    return await resolver.resolve(name, type);
  } catch (err) {
    pushError(errors, `DNS ${type} ${name}: ${err?.message ?? err}`);
    return null;
  }
}

export async function investigateEmail(raw) {
  const input = String(raw ?? "").trim().toLowerCase();
  if (!/^[^\s@]{1,64}@[^\s@]{1,253}\.[a-z]{2,}$/.test(input)) {
    return makeResult(String(raw ?? ""), { errors: [`invalid email format: ${JSON.stringify(raw ?? "")}`] });
  }
  const errors = [];
  const sources = ["dns:system-resolver"];
  const [local, domain] = input.split("@");

  const resolver = new dns.Resolver({ timeout: 8000, tries: 2 });
  const [mx, txt, spfDomain, dmarc] = await Promise.all([
    tryResolve(resolver, "MX", domain, errors),
    tryResolve(resolver, "TXT", domain, errors),
    tryResolve(resolver, "TXT", domain, errors),
    tryResolve(resolver, "TXT", `_dmarc.${domain}`, errors),
  ]);

  const txtFlat = (txt ?? []).flat().join(" ");
  const hasSpf = /v=spf1/i.test(txtFlat);
  const dmarcFlat = (dmarc ?? []).flat().join(" ");

  const data = {
    email: input,
    local_part: local,
    domain,
    domain_class: FREEMAIL.has(domain) ? "freemail (inference)" : DISPOSABLE.has(domain) ? "disposable (inference)" : "custom/organizational (inference)",
    mx: mx ? [...mx].sort((a, b) => a.priority - b.priority) : null,
    mail_server_present: mx ? mx.length > 0 : null,
    spf: { present: hasSpf, observed_txt: txt ?? null },
    dmarc: { present: /v=DMARC1/i.test(dmarcFlat), observed_txt: dmarc },
    _spf_domain_raw: spfDomain,
    note: "DNS-only OSINT. Deliverability/inbox existence is NOT tested (that would be an active probe).",
  };

  return makeResult(input, { data, sources, errors });
}
