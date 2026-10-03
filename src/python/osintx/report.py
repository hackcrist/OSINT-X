"""OSINT-X 09-REPORT: guarda resultados JSON/TXT/HTML con timestamp."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _safe(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "result"))[:60].strip("._-")
    return s or "result"


def save(result: dict, fmt: str = "json", outdir: str = "reports") -> str:
    """Guarda `result` (contrato common) en outdir. Retorna ruta creada.

    fmt: json | txt | html. Lanza ValueError si fmt inválido.
    """
    fmt = (fmt or "json").lower()
    if fmt not in ("json", "txt", "html"):
        raise ValueError(f"formato inválido: {fmt!r} (json|txt|html)")
    if not isinstance(result, dict) or "target" not in result:
        raise ValueError("result no cumple el contrato (falta 'target')")
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out / f"{_safe(str(result.get('target', 'result')))}_{ts}.{fmt}"
    if fmt == "json":
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "txt":
        lines = [f"OSINT-X report {result.get('retrieved_at', '')}",
                 f"target: {result.get('target', '')}",
                 f"status: {result.get('status', '')}", "",
                 "DATA:", json.dumps(result.get("data", {}), indent=2, ensure_ascii=False)[:20000],
                 "", "SOURCES:"]
        lines += [f"- {s}" for s in result.get("sources", [])]
        lines += ["", "ERRORS:"]
        lines += [f"- {e}" for e in result.get("errors", [])] or ["- (ninguno)"]
        path.write_text("\n".join(lines), encoding="utf-8")
    else:
        d = html.escape(json.dumps(result.get("data", {}), indent=2, ensure_ascii=False))
        items = "".join(f"<li>{html.escape(str(s))}</li>" for s in result.get("sources", []))
        errs = "".join(f"<li>{html.escape(str(e))}</li>" for e in result.get("errors", [])) or "<li>ninguno</li>"
        path.write_text(
            f"<!doctype html><html lang='es'><head><meta charset='utf-8'>"
            f"<title>OSINT-X {html.escape(str(result.get('target', '')))}</title></head><body>"
            f"<h1>OSINT-X</h1><p>target: <b>{html.escape(str(result.get('target', '')))}</b> "
            f"| status: {html.escape(str(result.get('status', '')))} "
            f"| retrieved_at: {html.escape(str(result.get('retrieved_at', '')))}</p>"
            f"<h2>Data</h2><pre>{d}</pre><h2>Sources</h2><ul>{items}</ul>"
            f"<h2>Errors</h2><ul>{errs}</ul></body></html>", encoding="utf-8")
    return str(path)
