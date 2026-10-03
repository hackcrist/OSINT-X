# Componentes

Archivos fuente y símbolos verificados en el repositorio.

---

## Especificación Técnica

### Python (`src/python/`)

Entrada: `cli.py` (menú 01-09, `00` sale; opción `09` guarda vía `report.save`). Paquete `osintx/`:

| Archivo | Símbolos |
| :--- | :--- |
| `common.py` | `doh_query`, `http_get`, `make_result`, `validate_domain` |
| `domain.py` | `lookup(domain)` |
| `portscan.py`, `subdomain.py`, `phone.py`, `username.py` | `scan`, `enumerate`, `lookup` respectivos |
| `ipinfo.py`, `email.py`, `url.py` | `lookup`, `analyze` respectivos |
| `report.py` | `save` (formatos JSON, TXT, HTML) |

Dependencias: solo biblioteca estándar (`urllib`, `socket`, `ssl`, `json`, `re`). Verificado en Python 3.14.

### Go (`src/go/`, módulo `osintx`, go 1.21)

| Archivo | Símbolos |
| :--- | :--- |
| `main.go` | Menú 01-09 y despacho |
| `common.go` | `Result`, `NewResult`, `httpGet`, `DefaultTimeout` |
| `domain.go` | `RunDomain`, `DomainData` |
| `portscan.go`, `subdomain.go`, `phone.go`, `username.go` | `RunPortscan`, `RunSubdomain`, etc. |
| `ipinfo.go`, `email.go`, `url.go` | Ejecutores por módulo |
| `report.go` | Persistencia del último resultado |

### JavaScript (`src/js/`, paquete `osint-x` 1.0.0, Node 18+)

Entrada `cli.mjs`; librerías en `lib/` (`common.mjs`, `domain.mjs`, `email.mjs`, `ipinfo.mjs`, `phone.mjs`, `portscan.mjs`, `report.mjs`, `subdomain.mjs`, `url.mjs`, `username.mjs`). Cero dependencias. Ejemplo verificado: `investigateDomain` en `lib/domain.mjs`.

### Shell (`src/shell/`)

Entrada `osintx.sh` (menú y atajo `módulo objetivo`), librería `lib/common.sh`, módulos en `modules/` y salidas en `reports/`.

---

## Consideraciones Críticas y Casos de Borde

1. **Timeouts:** toda red lleva tiempo límite; un origen lento no bloquea el resto.
2. **Sin dependencias externas:** las cuatro implementaciones usan lo estándar de cada lenguaje.
3. **Sin variables de entorno:** no se encontró configuración por entorno en el código revisado.
4. **Sin suite de tests:** no existe carpeta de pruebas en el repositorio.

---

## Ejemplo de Uso

```bash
cd src/python && python cli.py        # opción 01, dominio example.com
cd src/go && go run .                 # opción 01
cd src/js && node cli.mjs             # opción 01
cd src/shell && ./osintx.sh 01 example.com
```
