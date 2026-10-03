"""OSINT-X 04-PHONE: normalización E.164 + país por prefijo (público).

No revela operador ni titular: sin fuente pública verificable el
operador se reporta como no disponible. Sin datos privados.
"""
from __future__ import annotations

import re

from .common import make_result

# Prefijo -> país (tabla pública ITU, ~20 entradas). Clave más larga gana.
PREFIXES = {
    "1": "US/CA (NANP)", "7": "RU/KZ", "20": "EG", "27": "ZA",
    "33": "FR", "34": "ES", "39": "IT", "44": "GB", "49": "DE",
    "52": "MX", "53": "CU", "54": "AR", "55": "BR", "56": "CL",
    "57": "CO", "58": "VE", "51": "PE", "506": "CR", "507": "PA",
    "351": "PT", "34": "ES", "52": "MX", "81": "JP", "86": "CN",
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
