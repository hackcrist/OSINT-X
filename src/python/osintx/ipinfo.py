"""OSINT-X 06-IPINFO: geo/ASN aproximados (ip-api.com) + reverse DNS.

La geolocalización por IP es aproximada (nivel ciudad/ISP), no exacta.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import urllib.parse

from .common import http_get, make_result


def lookup(ip: str) -> dict:
    errors: list[str] = []
    sources: list[str] = []
    target = (ip or "").strip()
    try:
        ip_obj = ipaddress.ip_address(target)
    except Exception:
        return make_result(ip, {"input_observed": ip}, [],
                           [f"IP inválida: {ip!r}"], "error")

    geo: dict = {}
    if not ip_obj.is_global:
        errors.append(f"IP no pública ({target}): consulta remota omitida; solo reverse DNS")
    else:
        api_url = (f"http://ip-api.com/json/{urllib.parse.quote(target)}"
                   "?fields=status,message,country,regionName,city,isp,org,as,query")
        sources.append(api_url)
        r = http_get(api_url, timeout=10, accept="application/json")
        if r["ok"]:
            try:
                p = json.loads(r["body"] or "{}")
                if p.get("status") == "success":
                    geo = {"country_observed": p.get("country", ""),
                           "region_observed": p.get("regionName", ""),
                           "city_observed": p.get("city", ""),
                           "isp_observed": p.get("isp", ""),
                           "org_observed": p.get("org", ""),
                           "asn_observed": p.get("as", ""),
                           "query_observed": p.get("query", "")}
                else:
                    errors.append(f"ip-api: {p.get('message', 'fail')}")
            except Exception as e:
                errors.append(f"ip-api JSON inválido: {e}")
        else:
            errors.append(f"ip-api: {r['error']}")

    try:
        rev, _, _ = socket.gethostbyaddr(target)
        reverse = rev
    except Exception as e:
        reverse = ""
        errors.append(f"reverse DNS: {type(e).__name__}: {e}")
    sources.append(f"socket.gethostbyaddr({target}) [reverse DNS observado]")

    data = {"ip_observed": target, **geo, "reverse_dns_observed": reverse,
            "note": "geolocalización aproximada por IP; no identifica persona ni domicilio."}
    status = "ok" if geo and not errors else ("partial" if geo or reverse else "error")
    return make_result(target, data, sources, errors, status)
