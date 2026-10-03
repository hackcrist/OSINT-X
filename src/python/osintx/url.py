"""OSINT-X 08-URL: headers + cadena de redirects + cert TLS + tech detect.

Solo GET público con timeouts; no se envían credenciales ni se
evaden controles. observed = headers/status/cert; inferred = tecnología.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.parse
import urllib.request

from .common import USER_AGENT, make_result


class _Chain(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.chain: list[dict] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append({"code_observed": code, "to_observed": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, timeout: int = 10) -> dict:
    handler = _Chain()
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(1_000_000)
            html = raw.decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "headers": dict(resp.headers.items()),
                    "final_url": resp.geturl(), "html": html, "chain": handler.chain, "error": ""}
    except Exception as e:
        return {"ok": False, "status": 0, "headers": {}, "final_url": url,
                "html": "", "chain": handler.chain, "error": f"{type(e).__name__}: {e}"}


def _cert(host: str, timeout: int = 8) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                c = tls.getpeercert() or {}
        subj = {k: v for t in c.get("subject", []) for k, v in t}
        iss = {k: v for t in c.get("issuer", []) for k, v in t}
        return {"subject_observed": subj, "issuer_observed": iss,
                "notAfter_observed": c.get("notAfter", ""),
                "san_observed": [v for t, v in c.get("subjectAltName", [])]}
    except Exception as e:
        return {"error": f"TLS: {type(e).__name__}: {e}"}


def _tech(headers: dict, html: str) -> list[str]:
    found: list[str] = []
    low_h = {k.lower(): v for k, v in headers.items()}
    server = low_h.get("server", "")
    powered = low_h.get("x-powered-by", "")
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    if m:
        gen = m.group(1)
    blob = f"{server} {powered} {gen} {html[:20000]}".lower()
    rules = [("wordpress", "wp-content"), ("drupal", "drupal"), ("joomla", "joomla"),
             ("next.js", "__next_data__"), ("react", "react"), ("nginx", "nginx"),
             ("apache", "apache"), ("cloudflare", "cloudflare"), ("php", "x-powered-by: php"),
             ("django", "csrftoken"), ("shopify", "shopify")]
    text = f"{server} {powered} {gen}".lower() + "\n" + blob
    for label, sig in rules:
        if sig in text and label not in found:
            found.append(label)
    if gen and gen not in found:
        found.append(f"generator:{gen[:80]}")
    return found


def analyze(url: str) -> dict:
    errors: list[str] = []
    u = (url or "").strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    try:
        parts = urllib.parse.urlparse(u)
        if not parts.hostname or "." not in parts.hostname:
            raise ValueError("hostname inválido")
        host = parts.hostname
    except Exception:
        return make_result(url, {"input_observed": url}, [], [f"URL inválida: {url!r}"], "error")

    r = _fetch(u)
    sources = [u]
    if not r["ok"]:
        errors.append(r["error"])
        return make_result(u, {"input_observed": url, "fetch_error_observed": r["error"],
                               "redirect_chain_observed": r["chain"]}, sources, errors, "error")
    cert = _cert(host) if parts.scheme == "https" else {"note": "sin TLS (URL http)"}
    if "error" in cert:
        errors.append(cert["error"])
    tech = _tech(r["headers"], r["html"])
    data = {"input_observed": url, "final_url_observed": r["final_url"],
            "http_status_observed": r["status"],
            "redirect_chain_observed": r["chain"],
            "headers_observed": r["headers"],
            "cert_observed": cert, "tech_inferred": tech,
            "html_snippet_observed": r["html"][:2000]}
    return make_result(u, data, sources, errors, "ok" if not errors else "partial")
