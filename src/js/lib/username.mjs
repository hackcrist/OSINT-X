/**
 * OSINT-X · 05 USERNAME
 * Public-presence check: HEAD (fallback GET) against profile URLs.
 * 200 → found, 404 → not found, anything else → unknown.
 * No login, no bypass, timeouts on every request.
 */
import { httpGet, httpHead, makeResult } from "./common.mjs";

const PLATFORMS = [
  { id: "github", url: (u) => `https://github.com/${u}` },
  { id: "gitlab", url: (u) => `https://gitlab.com/${u}` },
  { id: "x", url: (u) => `https://x.com/${u}` },
  { id: "instagram", url: (u) => `https://www.instagram.com/${u}/` },
  { id: "reddit", url: (u) => `https://www.reddit.com/user/${u}/` },
  { id: "medium", url: (u) => `https://medium.com/@${u}` },
  { id: "devto", url: (u) => `https://dev.to/${u}` },
  { id: "npm", url: (u) => `https://www.npmjs.com/~${u}` },
  { id: "pypi", url: (u) => `https://pypi.org/user/${u}/` },
  { id: "stackoverflow", url: (u) => `https://stackoverflow.com/users/${u}` },
];

const PER_REQUEST_TIMEOUT = 10_000;

async function probe(platform, username) {
  const profileUrl = platform.url(username);
  try {
    const head = await httpHead(profileUrl, { timeoutMs: PER_REQUEST_TIMEOUT });
    if (head.status === 200) return { platform: platform.id, profile_url: profileUrl, presence: "found", http_status: 200, observed_via: "HEAD" };
    if (head.status === 404) return { platform: platform.id, profile_url: profileUrl, presence: "not-found", http_status: 404, observed_via: "HEAD" };
    if (![403, 405, 501].includes(head.status)) {
      return { platform: platform.id, profile_url: profileUrl, presence: head.status === 200 ? "found" : "unknown", http_status: head.status, observed_via: "HEAD" };
    }
    // Servers that reject HEAD: one GET to disambiguate.
    const get = await httpGet(profileUrl, { timeoutMs: PER_REQUEST_TIMEOUT });
    if (get.status === 200) return { platform: platform.id, profile_url: profileUrl, presence: "found", http_status: 200, observed_via: "GET" };
    if (get.status === 404) return { platform: platform.id, profile_url: profileUrl, presence: "not-found", http_status: 404, observed_via: "GET" };
    return { platform: platform.id, profile_url: profileUrl, presence: "unknown", http_status: get.status, observed_via: "GET" };
  } catch (err) {
    return { platform: platform.id, profile_url: profileUrl, presence: "unknown", http_status: null, observed_via: null, error: err?.message ?? String(err) };
  }
}

export async function checkUsername(raw) {
  const username = String(raw ?? "").trim();
  if (!/^[A-Za-z0-9._-]{1,39}$/.test(username)) {
    return makeResult(String(raw ?? ""), {
      errors: ["invalid username: 1–39 chars, letters/digits/._- only"],
    });
  }
  const results = [];
  // Small sequential batches to avoid hammering remotes.
  const queue = [...PLATFORMS];
  while (queue.length > 0) {
    const batch = queue.splice(0, 3);
    results.push(...(await Promise.all(batch.map((p) => probe(p, encodeURIComponent(username))))));
  }
  const errors = results.filter((r) => r.error).map((r) => `${r.platform}: ${r.error}`);
  return makeResult(username, {
    data: {
      username,
      checked: results.length,
      found: results.filter((r) => r.presence === "found"),
      not_found: results.filter((r) => r.presence === "not-found").map((r) => r.platform),
      unknown: results.filter((r) => r.presence === "unknown"),
      note: "Presence means 'HTTP 200 on the public profile URL' — not identity verification. Some sites block bots; those stay 'unknown'.",
    },
    sources: results.map((r) => `https:${r.platform}`),
    errors,
  });
}
