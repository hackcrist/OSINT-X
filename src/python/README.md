# OSINT-X core Python (solo stdlib)

Paquete `osintx` + consola `cli.py`. Sin dependencias externas.

## Estructura

```text
src/python/
├── cli.py            # consola 01-09 + 00 EXIT
├── osintx/
│   ├── __init__.py
│   ├── common.py     # contrato salida + http_get + DoH helper
│   ├── domain.py     # lookup(domain)
│   ├── portscan.py   # scan(host, ports?, timeout=2.0)
│   ├── subdomain.py  # enumerate(domain)
│   ├── phone.py      # lookup(raw)
│   ├── username.py   # lookup(username)
│   ├── ipinfo.py     # lookup(ip)
│   ├── email.py      # lookup(email)
│   ├── url.py        # analyze(url)
│   └── report.py     # save(result, fmt, outdir)
```

## Uso

```bash
cd src/python
python cli.py            # menú interactivo
# o
python -m cli            # equivalente
```

Uso programático:

```python
from osintx import domain, report
r = domain.lookup("example.com")   # dict status/target/data/sources/retrieved_at/errors
print(r["status"], r["errors"])
path = report.save(r, fmt="json", outdir="../../reports")
```

## Contrato de salida

Todos los módulos devuelven:

```json
{"status": "ok|partial|error", "target": "...", "data": {},
 "sources": ["..."], "retrieved_at": "ISO8601-UTC", "errors": ["..."]}
```

Claves `*_observed` = dato medido; `*_inferred` = conjetura etiquetada.

## Reglas

- Solo información pública y targets autorizados (portscan solo propio/autorizado).
- Timeouts en toda red (DoH/HTTP 10-20 s, TCP 2 s, TLS 8 s).
- Sin bypass de auth/CAPTCHA/login; los 401/403/429 se reportan como `unknown`/error.
- Sin credenciales ni secretos en código.
- Verificación pendiente de red: este entorno puede no tener internet;
  los helpers registran el error en `errors` en vez de fabricar datos.
