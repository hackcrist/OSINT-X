"""OSINT-X consola (solo stdlib). Uso: python -m cli  o  python cli.py
desde src/python/. Menú 01-09 + 00 EXIT. Cada resultado puede
guardarse vía 09-REPORT (JSON/TXT/HTML).
"""
from __future__ import annotations

import json
import sys
import textwrap

# ── codificación robusta para terminales Windows ───────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ── imports del paquete ─────────────────────────────────────────────────────
try:
    from osintx import domain, email, ipinfo, phone, portscan, subdomain, url, username
    from osintx import report as report_mod
except ImportError:
    sys.path.insert(0, ".")
    from osintx import domain, email, ipinfo, phone, portscan, subdomain, url, username
    from osintx import report as report_mod

# ── soporte de color ANSI ────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_CYAN   = "\033[36m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_DIM    = "\033[2m"

_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Aplica código ANSI solo si el terminal lo soporta."""
    return f"{code}{text}{_RESET}" if _USE_COLOR else text


BANNER = textwrap.dedent(f"""
  {'─' * 58}
   OSINT-X  │  Inteligencia de fuentes abiertas (pasivo)
   Uso responsable: solo targets propios o con autorización.
  {'─' * 58}
""")

MENU = """
  01  DOMAIN      02  PORTSCAN    03  SUBDOMAIN
  04  PHONE       05  USERNAME    06  IPINFO
  07  EMAIL       08  URL         09  REPORT
  00  EXIT
"""

_EXIT_CMDS = {"00", "0", "exit", "quit", "q"}

# Almacena el último resultado para la opción REPORT
last_result: dict | None = None


# ── helpers de I/O ──────────────────────────────────────────────────────────

def _ask(prompt: str) -> str:
    """Lectura de línea; devuelve '' en EOF/Ctrl-C."""
    try:
        return input(_c(_CYAN, prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _hr(char: str = "─", width: int = 60) -> None:
    print(_c(_DIM, char * width))


def _show(result: dict) -> None:
    """Imprime el resultado con formato y lo guarda como último resultado."""
    global last_result
    last_result = result

    status = result.get("status", "?")
    color  = _GREEN if status == "ok" else (_YELLOW if status == "partial" else _RED)

    _hr()
    print(f"  {_c(_BOLD, 'target')}: {result.get('target', '')}   "
          f"{_c(_BOLD, 'status')}: {_c(color, status)}   "
          f"{_c(_DIM, result.get('retrieved_at', ''))}")
    _hr()

    body = json.dumps(result.get("data", {}), indent=2, ensure_ascii=False)
    for line in body[:8000].splitlines():
        print(f"  {line}")

    errors = result.get("errors", [])
    if errors:
        print()
        print(_c(_YELLOW, "  ── errores observados ──"))
        for err in errors[:15]:
            print(f"  {_c(_YELLOW, '!')} {err}")

    sources = result.get("sources", [])
    print()
    print(_c(_DIM, f"  fuentes: {len(sources)}  │  guarda el resultado con opción 09"))
    _hr()


# ── acción REPORT ───────────────────────────────────────────────────────────

def _do_report() -> None:
    if not last_result:
        print(_c(_YELLOW, "  Sin resultado previo: ejecuta primero un módulo 01-08."))
        return
    fmt    = _ask("Formato [json/txt/html] (json): ").lower() or "json"
    outdir = _ask("Carpeta de salida (reports): ") or "reports"
    if fmt not in ("json", "txt", "html"):
        print(_c(_RED, f"  Formato '{fmt}' inválido. Usa json, txt o html."))
        return
    try:
        path = report_mod.save(last_result, fmt=fmt, outdir=outdir)
        print(_c(_GREEN, f"  Guardado: {path}"))
    except Exception as exc:
        print(_c(_RED, f"  Error al guardar: {type(exc).__name__}: {exc}"))


# ── parseo de puertos ────────────────────────────────────────────────────────

def _parse_ports(raw: str) -> list[int] | None:
    """Convierte '80,443;8080' en [80, 443, 8080]. Devuelve None si vacío."""
    if not raw.strip():
        return None
    ports: list[int] = []
    for p in raw.replace(";", ",").split(","):
        p = p.strip()
        if p.isdigit():
            ports.append(int(p))
        elif p:
            print(_c(_YELLOW, f"  ! Ignorando valor no numérico: '{p}'"))
    return ports or None


# ── dispatcher ───────────────────────────────────────────────────────────────

def _run_option(opt: str) -> bool:
    """Ejecuta la opción elegida. Devuelve False para indicar salida."""
    if opt in _EXIT_CMDS:
        print(_c(_DIM, "  Saliendo. Hasta pronto."))
        return False

    if opt == "01":
        t = _ask("Dominio: ")
        if t:
            _show(domain.lookup(t))

    elif opt == "02":
        h = _ask("Host (autorizado): ")
        if not h:
            return True
        ports = _parse_ports(_ask("Puertos coma-separados (vacío = predeterminados): "))
        print(_c(_DIM, "  Escaneando… (timeout 2 s/puerto)"))
        _show(portscan.scan(h, ports))

    elif opt == "03":
        t = _ask("Dominio: ")
        if t:
            _show(subdomain.enumerate(t))

    elif opt == "04":
        t = _ask("Teléfono (formato +34…): ")
        if t:
            _show(phone.lookup(t))

    elif opt == "05":
        t = _ask("Username: ")
        if t:
            print(_c(_DIM, "  Consultando plataformas… (puede tardar ~15 s)"))
            _show(username.lookup(t))

    elif opt == "06":
        t = _ask("IP (IPv4 o IPv6): ")
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

    elif opt == "":
        pass  # Enter en blanco → redibujar menú

    else:
        print(_c(_RED, f"  Opción '{opt}' inválida. Usa 01-09 o 00 para salir."))

    return True


# ── punto de entrada ─────────────────────────────────────────────────────────

def main() -> int:
    print(BANNER)
    while True:
        print(MENU)
        opt = _ask("OSINT-X> ")
        # Normalizar: "1" -> "01" (igual que Shell y JS).
        if len(opt) == 1 and opt.isdigit():
            opt = "0" + opt
        try:
            if not _run_option(opt):
                return 0
        except KeyboardInterrupt:
            print()  # Ctrl-C durante una operación → volver al menú
        except Exception as exc:
            print(_c(_RED, f"  Error inesperado: {type(exc).__name__}: {exc}"))


if __name__ == "__main__":
    raise SystemExit(main())
