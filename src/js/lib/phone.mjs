/**
 * OSINT-X · 04 PHONE
 * Offline phone-number parsing: E.164 normalization, country detection
 * from public dial-code table, length/format checks.
 * No external lookup (carrier data needs a paid/public API key) — carrier
 * is reported as unavailable, never guessed silently.
 */

import { makeResult } from "./common.mjs";

// E.164-relevant dial codes (subset covering common regions).
const DIAL_CODES = [
  { code: "1", region: "NANP (US/CA/Caribbean)", countries: ["US", "CA"], min: 11, max: 11 },
  { code: "7", region: "RU/KZ", countries: ["RU", "KZ"], min: 11, max: 11 },
  { code: "20", region: "EG", countries: ["EG"], min: 12, max: 12 },
  { code: "27", region: "ZA", countries: ["ZA"], min: 11, max: 11 },
  { code: "30", region: "GR", countries: ["GR"], min: 12, max: 12 },
  { code: "31", region: "NL", countries: ["NL"], min: 11, max: 11 },
  { code: "32", region: "BE", countries: ["BE"], min: 11, max: 11 },
  { code: "33", region: "FR", countries: ["FR"], min: 11, max: 11 },
  { code: "34", region: "ES", countries: ["ES"], min: 11, max: 11 },
  { code: "39", region: "IT", countries: ["IT"], min: 12, max: 13 },
  { code: "40", region: "RO", countries: ["RO"], min: 11, max: 11 },
  { code: "41", region: "CH", countries: ["CH"], min: 11, max: 11 },
  { code: "43", region: "AT", countries: ["AT"], min: 12, max: 13 },
  { code: "44", region: "UK", countries: ["GB"], min: 12, max: 12 },
  { code: "45", region: "DK", countries: ["DK"], min: 10, max: 10 },
  { code: "46", region: "SE", countries: ["SE"], min: 11, max: 12 },
  { code: "47", region: "NO", countries: ["NO"], min: 10, max: 10 },
  { code: "48", region: "PL", countries: ["PL"], min: 11, max: 11 },
  { code: "49", region: "DE", countries: ["DE"], min: 12, max: 13 },
  { code: "51", region: "PE", countries: ["PE"], min: 11, max: 11 },
  { code: "52", region: "MX", countries: ["MX"], min: 12, max: 12 },
  { code: "53", region: "CU", countries: ["CU"], min: 10, max: 10 },
  { code: "54", region: "AR", countries: ["AR"], min: 12, max: 13 },
  { code: "55", region: "BR", countries: ["BR"], min: 12, max: 13 },
  { code: "56", region: "CL", countries: ["CL"], min: 11, max: 11 },
  { code: "57", region: "CO", countries: ["CO"], min: 12, max: 12 },
  { code: "58", region: "VE", countries: ["VE"], min: 12, max: 12 },
  { code: "81", region: "JP", countries: ["JP"], min: 12, max: 13 },
  { code: "82", region: "KR", countries: ["KR"], min: 12, max: 13 },
  { code: "84", region: "VN", countries: ["VN"], min: 11, max: 12 },
  { code: "86", region: "CN", countries: ["CN"], min: 13, max: 13 },
  { code: "91", region: "IN", countries: ["IN"], min: 12, max: 12 },
  { code: "351", region: "PT", countries: ["PT"], min: 12, max: 12 },
  { code: "353", region: "IE", countries: ["IE"], min: 12, max: 13 },
  { code: "380", region: "UA", countries: ["UA"], min: 12, max: 12 },
  { code: "505", region: "NI", countries: ["NI"], min: 11, max: 11 },
  { code: "506", region: "CR", countries: ["CR"], min: 11, max: 11 },
  { code: "507", region: "PA", countries: ["PA"], min: 11, max: 11 },
  { code: "809", region: "DO", countries: ["DO"], min: 11, max: 11 },
  { code: "829", region: "DO", countries: ["DO"], min: 11, max: 11 },
  { code: "849", region: "DO", countries: ["DO"], min: 11, max: 11 },
];

export function analyzePhone(raw) {
  const input = String(raw ?? "").trim();
  if (!input) return makeResult("", { errors: ["phone number is required"] });

  const errors = [];
  const cleaned = input.replace(/[.\-()\s]/g, "");
  if (!/^\+?\d+$/.test(cleaned)) {
    return makeResult(input, { errors: [`invalid characters in ${JSON.stringify(input)} (digits, spaces, +-(). only)`] });
  }
  const e164 = cleaned.startsWith("+") ? cleaned : `+${cleaned}`;
  const digits = e164.slice(1);

  if (digits.length < 7 || digits.length > 15) {
    errors.push(`length ${digits.length} outside E.164 range 7–15`);
  }

  // Longest-prefix match on dial code.
  let match = null;
  for (const dc of DIAL_CODES) {
    if (digits.startsWith(dc.code) && (!match || dc.code.length > match.code.length)) match = dc;
  }

  const national = match ? digits.slice(match.code.length) : null;
  const data = {
    input,
    e164,
    valid_format: errors.length === 0 && match !== null,
    country: match ? { dial_code: `+${match.code}`, region: match.region, countries: match.countries } : null,
    national_number: national,
    national_length_ok: match ? (national.length >= match.min - match.code.length - 1 && national.length <= 15) : null,
    carrier: null,
    carrier_note: "Operator lookup requires a public directory/API source; not inferred offline (unavailable).",
  };
  if (!match) errors.push("country dial code not recognized (number kept in E.164, country unknown)");
  if (national !== null && match && (digits.length < match.min || digits.length > match.max)) {
    errors.push(`expected ${match.min}–${match.max} digits for +${match.code}, got ${digits.length}`);
  }

  return makeResult(input, { data, sources: ["offline:e164-dial-table"], errors });
}
