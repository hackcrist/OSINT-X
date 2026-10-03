"""OSINT-X 01-DOMAIN: DNS (DoH Cloudflare) + IPs + RDAP + MX/TXT/NS.

Fuentes públicas: DoH Cloudflare, socket.getaddrinfo (DNS local),
RDAP https://rdap.org/domain/X. Sin WHOIS legacy crudo.
"""
from __future__ import annotations

import json
import socket

from .common import doh_query, http_get, make_result, validate_domain


def _resolve_ips(domain: str, errors: list[str]) -> list[str]:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)
        try:
            infos = socket.getaddrinfo(domain, None, family=socket.AF_UNSPEC,
                                       type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old)
        ips: list[str] = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception as e:
        errors.append(f"getaddrinfo({domain}): {type(e).__name__}: {e}")
        return []


def lookup(domain: str) -> dict:
    """Investiga un dominio. Solo lectura, con timeouts. Requiere target autorizado."""
    errors: list[str] = []
    sources: list[str] = []
    try:
        dom = validate_domain(domain)
    except ValueError as e:
        return make_result(domain, {"domain_observed": domain}, [], [str(e)], "error")

    data: dict = {"domain_observed": dom}
    for qtype, key in (("A", "a_observed"), ("AAAA", "aaaa_observed"),
                       ("MX", "mx_observed"), ("TXT", "txt_observed"),
                       ("NS", "ns_observed")):
        r = doh_query(dom, qtype)
        sources.append(r["source"])
        if r["ok"]:
            data[key] = r["answers"]
        else:
            data[key] = []
            errors.append(f"DoH {qtype}: {r['error']}")

    data["ips_observed"] = _resolve_ips(dom, errors)
    if data["ips_observed"]:
        sources.append(f"socket.getaddrinfo({dom}) [DNS local del sistema]")

    # RDAP (público). rdap.org redirige al RIR/registrar correspondiente.
    rdap_url = f"https://rdap.org/domain/{dom}"
    sources.append(rdap_url)
    r = http_get(rdap_url, timeout=15, accept="application/json")
    if r["ok"]:
        try:
            payload = json.loads(r["body"] or "{}")
            data["rdap_observed"] = {
                "handle": payload.get("handle", ""),
                "status": payload.get("status", []),
                "entities": [str(e.get("handle", "")) for e in (payload.get("entities") or [])][:10],
                "nameservers": [str(n.get("ldhName", "")) for n in (payload.get("nameservers") or [])][:10],
                "events": [{k: ev.get(k, "") for k in ("eventAction", "eventDate")}
                           for ev in (payload.get("events") or [])][:10],
                "raw_truncated": (r["body"] or "")[:4000],
            }
        except Exception as e:
            errors.append(f"RDAP JSON inválido: {e}")
            data["rdap_observed"] = {}
    else:
        data["rdap_observed"] = {}
        errors.append(f"RDAP: {r['error']}")

    # Inferencia mínima y etiquetada.
    data["mail_config_inferred"] = (
        "dominio con MX publicado (probable correo entrante)"
        if data.get("mx_observed") else "sin MX observado (inferencia: correo entrante improbable)"
    )
    status = "ok" if not errors else ("partial" if data.get("a_observed") or data.get("ips_observed") else "error")
    return make_result(dom, data, sources, errors, status)
