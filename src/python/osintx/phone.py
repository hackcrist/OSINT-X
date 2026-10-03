"""OSINT-X 04-PHONE: normalización E.164 + país por prefijo (público).

No revela operador ni titular: sin fuente pública verificable el
operador se reporta como no disponible. Sin datos privados.
"""
from __future__ import annotations

import re

from .common import make_result

# Prefijo -> país (tabla pública ITU). Clave más larga gana (4→3→2→1).
PREFIXES: dict[str, str] = {
    # 1 dígito
    "1": "US/CA (NANP)", "7": "RU/KZ",
    # 2 dígitos
    "20": "EG", "27": "ZA", "30": "GR", "31": "NL", "32": "BE",
    "33": "FR", "34": "ES", "36": "HU", "39": "IT", "40": "RO",
    "41": "CH", "43": "AT", "44": "GB", "45": "DK", "46": "SE",
    "47": "NO", "48": "PL", "49": "DE",
    "51": "PE", "52": "MX", "53": "CU", "54": "AR", "55": "BR",
    "56": "CL", "57": "CO", "58": "VE",
    "61": "AU", "62": "ID", "63": "PH", "64": "NZ", "65": "SG",
    "66": "TH",
    "81": "JP", "82": "KR", "84": "VN", "86": "CN",
    "90": "TR", "91": "IN", "92": "PK", "93": "AF", "94": "LK",
    "95": "MM", "98": "IR",
    # 3 dígitos
    "351": "PT", "352": "LU", "353": "IE", "354": "IS", "355": "AL",
    "356": "MT", "357": "CY", "358": "FI", "359": "BG",
    "380": "UA", "381": "RS", "385": "HR", "386": "SI", "387": "BA",
    "506": "CR", "507": "PA", "509": "HT",
    "591": "BO", "593": "EC", "595": "PY", "598": "UY",
    "880": "BD", "886": "TW",
    "960": "MV", "961": "LB", "962": "JO", "963": "SY",
    "964": "IQ", "965": "KW", "966": "SA", "967": "YE",
    "968": "OM", "971": "AE", "972": "IL", "973": "BH",
    "974": "QA", "975": "BT", "976": "MN", "977": "NP",
}
E164_RE = re.compile(r"^\+\d{7,15}$")


def _normalize(raw: str) -> str:
    v = (raw or "").strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if v.startswith("00"):
        v = "+" + v[2:]
    if not v.startswith("+"):
        v = "+" + v.lstrip("+")
    v = "+" + re.sub(r"\D", "", v[1:])
    return v


def lookup(raw: str) -> dict:
    errors: list[str] = []
    sources = ["UIT-T E.164 (formato observado)", "tabla de prefijos OSINT-X (inferencia de país)"]
    e164 = _normalize(raw)
    valid = bool(E164_RE.match(e164))
    if not valid:
        errors.append(f"formato inválido tras normalizar: {e164!r} (se esperan 7-15 dígitos con +)")
        return make_result(raw, {"input_observed": raw, "e164_observed": e164,
                                 "valid_format_observed": False}, sources, errors, "error")
    digits = e164[1:]
    country_inferred, cc = "desconocido", ""
    for L in (4, 3, 2, 1):
        cand = digits[:L]
        if cand in PREFIXES:
            cc, country_inferred = cand, PREFIXES[cand]
            break
    national = digits[len(cc):] if cc else digits
    data = {"input_observed": raw, "e164_observed": e164,
            "valid_format_observed": True,
            "country_code_observed": cc, "national_number_observed": national,
            "country_inferred": country_inferred,
            "carrier_observed": "no disponible sin fuente pública verificable",
            "note": "El país por prefijo es inferencia de numeración, no geolocalización del titular."}
    return make_result(raw, data, sources, errors, "ok" if cc else "partial")
