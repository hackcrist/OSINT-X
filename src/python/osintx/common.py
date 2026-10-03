"""OSINT-X common helpers (solo stdlib).

Contrato de salida de todos los módulos:
{
  "status": "ok" | "partial" | "error",
  "target": str,
  "data": dict,
  "sources": [str],
  "retrieved_at": str (ISO8601 UTC),
  "errors": [str]
}
Reglas: solo info pública, sin fabricar datos, observado vs inferencia
separados en los módulos (claves *_observed / *_inferred).
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

USER_AGENT = "OSINT-X/1.0 (+passive-osint; authorized-use-only)"
DOH_URL = "https://cloudflare-dns.com/dns-query"


def now_iso() -> str:
    """Timestamp ISO8601 UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_result(target: str, data: dict | None = None,
                sources: list[str] | None = None,
                errors: list[str] | None = None,
                status: str = "ok") -> dict:
    errors = list(errors or [])
    if status not in ("ok", "partial", "error"):
        status = "ok"
    if errors and status == "ok":
        status = "partial"
    if status == "error" and not errors:
        errors = ["error no especificado"]
    return {
        "status": status,
        "target": str(target),
        "data": data or {},
        "sources": sources or [],
        "retrieved_at": now_iso(),
        "errors": errors,
    }


def http_get(url: str, timeout: int = 10,
             headers: dict | None = None,
             accept: str | None = None) -> dict:
    """GET simple con urllib. Nunca lanza: devuelve dict ok/status/headers/body/url/error.

    No sigue lógica de bypass: un 401/403/429 se reporta como observado.
    """
    req_headers = {"User-Agent": USER_AGENT}
    if accept:
        req_headers["Accept"] = accept
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(2_000_000)  # límite 2MB
            try:
                body = raw.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return {
                "ok": True,
                "status": resp.status,
                "headers": dict(resp.headers.items()),
                "body": body,
                "url": resp.geturl(),
                "error": "",
            }
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "headers": {},
                "body": "", "url": url,
                "error": f"HTTP {e.code} en {url}"}
    except urllib.error.URLError as e:
        return {"ok": False, "status": 0, "headers": {},
                "body": "", "url": url,
                "error": f"URL error en {url}: {e.reason}"}
    except Exception as e:  # timeout, etc. explícito
        return {"ok": False, "status": 0, "headers": {},
                "body": "", "url": url,
                "error": f"{type(e).__name__} en {url}: {e}"}


def doh_query(name: str, qtype: str = "A", timeout: int = 10) -> dict:
    """Consulta DNS-over-HTTPS (Cloudflare dns-json). Devuelve dict.

    Retorna {"ok", "answers": [...], "error", "source"} sin fabricar:
    si falla, answers=[] y error explícito.
    """
    name = name.strip().lower().rstrip(".")
    if not name:
        return {"ok": False, "answers": [], "error": "nombre vacío", "source": DOH_URL}
    params = urllib.parse.urlencode({"name": name, "type": qtype})
    url = f"{DOH_URL}?{params}"
    r = http_get(url, timeout=timeout, accept="application/dns-json")
    if not r["ok"]:
        return {"ok": False, "answers": [], "error": r["error"], "source": url}
    try:
        payload = json.loads(r["body"] or "{}")
    except Exception as e:
        return {"ok": False, "answers": [], "error": f"DoH JSON inválido: {e}", "source": url}
    answers = []
    for a in payload.get("Answer") or []:
        data = str(a.get("data", "")).strip()
        if data:
            answers.append(data)
    return {"ok": True, "answers": answers, "error": "", "source": url}


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*(\.[a-z]{2,})$")


def validate_domain(value: str) -> str:
    """Normaliza y valida dominio. Lanza ValueError si inválido."""
    v = (value or "").strip().lower().rstrip(".")
    if not v or len(v) > 253 or not DOMAIN_RE.match(v):
        raise ValueError(f"dominio inválido: {value!r}")
    return v
