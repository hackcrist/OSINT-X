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
    else:  # html
        tgt   = html.escape(str(result.get("target", "")))
        stat  = html.escape(str(result.get("status", "")))
        ts    = html.escape(str(result.get("retrieved_at", "")))
        d     = html.escape(json.dumps(result.get("data", {}), indent=2, ensure_ascii=False))
        items = "".join(f"<li><a href='{html.escape(str(s))}' rel='noopener'>{html.escape(str(s))}</a></li>"
                        for s in result.get("sources", []))
        errs  = ("".join(f"<li>{html.escape(str(e))}</li>" for e in result.get("errors", []))
                 or "<li><em>ninguno</em></li>")
        stat_color = {"ok": "#22c55e", "partial": "#f59e0b", "error": "#ef4444"}.get(
            result.get("status", ""), "#94a3b8")
        path.write_text(
            f"""<!doctype html>
<html lang='es'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>OSINT-X – {tgt}</title>
  <style>
    body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:1.5rem}}
    h1{{color:#38bdf8;margin-bottom:.25rem}}h2{{color:#7dd3fc;border-bottom:1px solid #1e3a5f;padding-bottom:.25rem}}
    .meta{{font-size:.85rem;color:#94a3b8;margin-bottom:1.5rem}}
    .badge{{display:inline-block;padding:.2em .6em;border-radius:.4em;font-weight:700;
            background:{stat_color};color:#000;margin-left:.5rem}}
    pre{{background:#1e293b;padding:1rem;border-radius:.5rem;overflow:auto;font-size:.8rem;line-height:1.5}}
    ul{{background:#1e293b;border-radius:.5rem;padding:1rem 1rem 1rem 2rem;margin:0}}
    li{{margin:.25rem 0;word-break:break-all}}a{{color:#38bdf8}}
    .section{{margin:1.5rem 0}}
  </style>
</head>
<body>
  <h1>OSINT-X</h1>
  <div class='meta'>
    <strong>target:</strong> {tgt}
    <span class='badge'>{stat}</span>
    &nbsp;|&nbsp; <strong>retrieved_at:</strong> {ts}
  </div>
  <div class='section'><h2>Data</h2><pre>{d}</pre></div>
  <div class='section'><h2>Sources</h2><ul>{items}</ul></div>
  <div class='section'><h2>Errors</h2><ul>{errs}</ul></div>
</body></html>""",
            encoding="utf-8")
    return str(path)
