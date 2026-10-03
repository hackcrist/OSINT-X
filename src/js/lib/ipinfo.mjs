/**
 * OSINT-X · 06 IPINFO
 * Geolocation/ASN/ISP via ip-api.com (no key) + reverse DNS via dns/promises.
 * Public information only; approximate geolocation.
 */
import dns from "node:dns/promises";
import { httpGetJson, isIp, makeResult, pushError } from "./common.mjs";

const IP_API = (ip) =>
  `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query`;

export async function investigateIp(raw) {
  const input = String(raw ?? "").trim();
  const errors = [];
  const sources = [];
  if (!isIp(input)) {
    return makeResult(input, { errors: [`invalid IP address: ${JSON.stringify(raw ?? "")}`] });
  }

  const data = { ip: input };

  try {
    const { json } = await httpGetJson(IP_API(input), { timeoutMs: 10_000 });
    sources.push("ip-api.com");
    if (json?.status !== "success") {
      pushError(errors, `ip-api: ${json?.message ?? "lookup failed"}`);
      data.ipapi = null;
    } else {
      data.geo = {
        country: json.country ?? null,
        country_code: json.countryCode ?? null,
        region: json.regionName ?? null,
        city: json.city ?? null,
        zip: json.zip ?? null,
        lat: json.lat ?? null,
        lon: json.lon ?? null,
        timezone: json.timezone ?? null,
      };
      data.network = {
        asn: json.as ?? null,
        isp: json.isp ?? null,
        org: json.org ?? null,
        mobile: json.mobile ?? null,
        proxy: json.proxy ?? null,
        hosting: json.hosting ?? null,
      };
      data.ipapi_reverse_hint = json.reverse ?? null;
      data.note = "Geolocation is approximate (city-level at best); mobile/proxy/hosting are ip-api inferences.";
    }
  } catch (err) {
    pushError(errors, `ip-api: ${err?.message ?? err}`);
    data.ipapi = null;
  }

  try {
    const names = await dns.reverse(input);
    sources.push("dns:reverse");
    data.reverse_dns = names;
  } catch (err) {
    pushError(errors, `reverse-DNS: ${err?.message ?? err}`);
    data.reverse_dns = null;
  }

  return makeResult(input, { data, sources, errors });
}
