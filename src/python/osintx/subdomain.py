"""OSINT-X 03-SUBDOMAIN: enumeración pasiva (crt.sh CT) + verificación DNS
+ wordlist mínima embebida (verificada por DNS, no fuerza bruta agresiva).
"""
from __future__ import annotations

import json
import socket
import urllib.parse

from .common import http_get, make_result, validate_domain

WORDLIST = ["www", "mail", "ftp", "api", "dev", "test", "blog", "shop",
            "vpn", "admin", "portal", "ns1", "ns2", "cdn", "static", "app",
            "webmail", "smtp", "owa", "intranet", "m", "mobile"]


def _resolves(name: str) -> bool:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        try:
            socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old)
        return True
    except Exception:
        return False


def enumerate(domain: str, verify_dns: bool = True, use_wordlist: bool = True) -> dict:  # noqa: A002
    errors: list[str] = []
    sources: list[str] = []
    try:
        dom = validate_domain(domain)
    except ValueError as e:
        return make_result(domain, {}, [], [str(e)], "error")

    crt_url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dom)}&output=json"
    sources.append(crt_url)
    found: dict[str, str] = {}
    r = http_get(crt_url, timeout=20, accept="application/json")
    if r["ok"]:
        try:
            payload = json.loads(r["body"] or "[]")
            for row in payload if isinstance(payload, list) else []:
                nv = str(row.get("name_value", ""))
                for cand in nv.splitlines():
                    cand = cand.strip().lower().rstrip(".")
                    if cand and (cand == dom or cand.endswith("." + dom)):
                        found.setdefault(cand, "crt.sh (CT log observado)")
        except Exception as e:
            errors.append(f"crt.sh JSON inválido: {e}")
    else:
        errors.append(f"crt.sh: {r['error']}")

    if use_wordlist:
        sources.append("wordlist embebida OSINT-X (inferencia de candidatos)")
        for w in WORDLIST:
            cand = f"{w}.{dom}"
            found.setdefault(cand, "wordlist embebida (candidato inferido)")

    data_list = []
    for name in sorted(found):
        origin = found[name]
        if verify_dns:
            ok = _resolves(name)
            data_list.append({"subdomain": name, "origin": origin,
                              "resolves_observed": ok})
        else:
            data_list.append({"subdomain": name, "origin": origin,
                              "resolves_observed": None})
    verified = sum(1 for d in data_list if d["resolves_observed"] is True)
    sources.append("socket.getaddrinfo (verificación DNS observada)")
    data = {"domain_observed": dom, "total_candidates": len(data_list),
            "verified_count_observed": verified, "subdomains": data_list}
    status = "ok" if verified else ("partial" if data_list else "error")
    if not data_list and not errors:
        errors.append("sin candidatos")
    return make_result(dom, data, sources, errors, status)
