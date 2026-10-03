"""OSINT-X consola (solo stdlib). Uso: python -m cli  o  python cli.py
desde src/python/. Menú 01-09 + 00 EXIT. Cada resultado puede
guardarse vía 09-REPORT (JSON/TXT/HTML).
"""
from __future__ import annotations

import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    from osintx import domain, email, ipinfo, phone, portscan, subdomain, url, username
    from osintx import report as report_mod
except ImportError:  # ejecución como script suelto
    sys.path.insert(0, ".")
    from osintx import domain, email, ipinfo, phone, portscan, subdomain, url, username
    from osintx import report as report_mod

BANNER = "OSINT-X :: consola pasiva (solo info pública / targets autorizados)"
MENU = """
 01 DOMAIN     02 PORTSCAN   03 SUBDOMAIN
 04 PHONE       05 USERNAME   06 IPINFO
 07 EMAIL       08 URL        09 REPORT (guardar último resultado)
 00 EXIT
"""

last_result: dict | None = None


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _show(result: dict) -> None:
    global last_result
    last_result = result
    print(f"\n[status={result.get('status')}] target={result.get('target')}")
    body = json.dumps(result.get("data", {}), indent=2, ensure_ascii=False)
    print(body[:6000])
    if result.get("errors"):
        print("-- errors --")
        for e in result["errors"][:10]:
            print(f" ! {e}")
    print(f"-- sources: {len(result.get('sources', []))} | retrieved_at: {result.get('retrieved_at')}")


def _do_report() -> None:
    if not last_result:
        print("Sin resultado previo: ejecuta un módulo 01-08 primero.")
        return
    fmt = _ask("Formato [json/txt/html] (json): ").lower() or "json"
    outdir = _ask("Carpeta salida (reports): ") or "reports"
    try:
        path = report_mod.save(last_result, fmt=fmt, outdir=outdir)
        print(f"Guardado: {path}")
    except Exception as e:
        print(f"Error al guardar: {type(e).__name__}: {e}")


def main() -> int:
    print(BANNER)
    print("Uso responsable: solo dominios/IPs propios o con autorización.")
    while True:
        print(MENU)
        opt = _ask("OSINT-X> ").strip()
        if opt in ("00", "0", "exit", "q", "") and opt == "":
            continue
        if opt in ("00", "0", "exit", "q"):
            print("Saliendo.")
            return 0
        try:
            if opt == "01":
                t = _ask("Dominio: ")
                if t:
                    _show(domain.lookup(t))
            elif opt == "02":
                h = _ask("Host (autorizado): ")
                p = _ask("Puertos coma-separados (vacío=por defecto): ")
                ports = None
                if p:
                    ports = [int(x) for x in p.replace(";", ",").split(",") if x.strip().isdigit()]
                if h:
                    print("Escaneando (timeout 2s/puerto)...")
                    _show(portscan.scan(h, ports))
            elif opt == "03":
                t = _ask("Dominio: ")
                if t:
                    _show(subdomain.enumerate(t))
            elif opt == "04":
                t = _ask("Teléfono (+34...): ")
                if t:
                    _show(phone.lookup(t))
            elif opt == "05":
                t = _ask("Username: ")
                if t:
                    print("Consultando plataformas (puede tardar)...")
                    _show(username.lookup(t))
            elif opt == "06":
                t = _ask("IP: ")
                if t:
                    _show(ipinfo.lookup(t))
            elif opt == "07":
                t = _ask("Email: ")
                if t:
                    _show(email.lookup(t))
            elif opt == "08":
                t = _ask("URL: ")
                if t:
                    _show(url.analyze(t))
            elif opt == "09":
                _do_report()
            else:
                print("Opción inválida. Usa 01-09 o 00.")
        except Exception as e:  # errores explícitos, sin traza cruda
            print(f"Error: {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
