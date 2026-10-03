"""OSINT-X 07-EMAIL: formato + dominio + MX (DoH). Sin verificación
de buzón (no se envía correo ni se hace SMTP VRFY). Solo lectura pública.
"""
from __future__ import annotations

import re
import socket

from .common import doh_query, make_result

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")


def lookup(email: str) -> dict:
    errors: list[str] = []
    sources: list[str] = []
    e = (email or "").strip().lower()
    valid = bool(EMAIL_RE.match(e))
    if not valid:
        return make_result(email, {"input_observed": email,
                                   "valid_format_observed": False}, [],
                           [f"email inválido: {email!r}"], "error")
    local, domain = e.rsplit("@", 1)
    mx = doh_query(domain, "MX")
    sources.append(mx["source"])
    mx_records = mx["answers"] if mx["ok"] else []
    if not mx["ok"]:
        errors.append(f"DoH MX: {mx['error']}")
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)
        try:
            infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old)
        domain_ips = sorted({sa[0] for _, _, _, _, sa in infos})
        sources.append(f"socket.getaddrinfo({domain}) [DNS local observado]")
    except Exception as ex:
        domain_ips = []
        errors.append(f"getaddrinfo({domain}): {type(ex).__name__}: {ex}")
    data = {"input_observed": e, "valid_format_observed": True,
            "local_part_observed": local, "domain_observed": domain,
            "mx_observed": mx_records, "domain_ips_observed": domain_ips,
            "deliverability_inferred": ("MX publicado (recepción probable)"
                                        if mx_records else "sin MX observado (recepción improbable)"),
            "note": "No se verifica existencia del buzón; solo registros públicos del dominio."}
    return make_result(e, data, sources, errors, "ok" if mx_records else "partial")
