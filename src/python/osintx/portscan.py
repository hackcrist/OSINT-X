"""OSINT-X 02-PORTSCAN: TCP connect + banner grab.

Solo usar contra hosts propios o con autorización escrita.
Timeout 2s por defecto. Distingue observado (estado/banner)
vs inferencia (servicio probable por puerto).
"""
from __future__ import annotations

import socket

from .common import make_result

SERVICE_GUESS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5900: "vnc",
    8080: "http-alt", 8443: "https-alt",
}
DEFAULT_PORTS = sorted(SERVICE_GUESS.keys())


def _resolve(host: str) -> tuple[str, str]:
    host = (host or "").strip()
    if not host:
        raise ValueError("host vacío")
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(10)
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC,
                                       type=socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old)
        return host, infos[0][4][0]
    except Exception as e:
        raise ValueError(f"no se pudo resolver {host!r}: {e}") from e


def _probe(ip: str, port: int, timeout: float = 2.0) -> dict:
    entry = {"port": port, "status_observed": "closed",
             "service_inferred": SERVICE_GUESS.get(port, "unknown"),
             "banner_observed": ""}
    s = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6,
                      socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        entry["status_observed"] = "open"
        try:
            try:  # algunos servicios envían banner sin pedir
                chunk = s.recv(1024)
            except socket.timeout:
                chunk = b""
            if not chunk and port in (80, 8080, 8443):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                    chunk = s.recv(1024)
                except Exception:
                    chunk = b""
            entry["banner_observed"] = chunk.decode("utf-8", errors="replace").strip()[:500]
        except Exception as e:
            entry["banner_observed"] = ""
            entry.setdefault("note", f"banner no legible: {e}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # cerrado/filtrado: se reporta como closed (observado)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return entry


def scan(host: str, ports: list[int] | None = None, timeout: float = 2.0) -> dict:
    """Escanea puertos TCP. `ports` validado (1-65535, máx 100)."""
    errors: list[str] = []
    sources: list[str] = []
    try:
        target, ip = _resolve(host)
    except ValueError as e:
        return make_result(host, {"host_observed": host}, [], [str(e)], "error")
    plist = ports or list(DEFAULT_PORTS)
    try:
        plist = [int(p) for p in plist]
    except Exception:
        return make_result(host, {}, [], ["lista de puertos inválida"], "error")
    if len(plist) > 100:
        return make_result(host, {}, [], ["máximo 100 puertos por ejecución"], "error")
    for p in plist:
        if not 1 <= p <= 65535:
            return make_result(host, {}, [], [f"puerto fuera de rango: {p}"], "error")

    results = [_probe(ip, p, timeout) for p in sorted(set(plist))]
    sources = [f"tcp-connect://{ip}:{r['port']} (observado) "
               f"timeout={timeout}s" for r in results]
    n_open = sum(1 for r in results if r["status_observed"] == "open")
    data = {"host_observed": target, "resolved_ip_observed": ip,
            "open_count_observed": n_open, "ports": results,
            "note": "service_inferred es conjetura por número de puerto, no fingerprinting."}
    return make_result(target, data, sources, errors,
                       "ok" if n_open or not errors else "partial")
