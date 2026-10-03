# Configuración

Variables de entorno y valores por defecto reales del código.

---

## Especificación Técnica

| Variable | Dónde | Defecto | Efecto |
| :--- | :--- | :--- | :--- |
| `OSINTX_TIMEOUT` | `src/shell/lib/common.sh` | `10` | Segundos de timeout para `curl` |
| `OSINTX_UA` | `src/shell/lib/common.sh` | `OSINT-X/1.0.0` | User-Agent de las peticiones Shell |
| `OSINTX_VERSION` | `src/shell/lib/common.sh` | `1.0.0` | Versión mostrada por Shell |

Python, Go y JavaScript no usan variables de entorno en el código revisado. Sus timeouts son constantes internas: Go 5 segundos (`DefaultTimeout`), JS 8 y 10 segundos, Python de 10 a 15 según módulo.

---

## Consideraciones Críticas y Casos de Borde

1. **Sin secretos:** ninguna variable transporta claves ni tokens.
2. **Solo Shell es configurable:** para cambiar tiempos en los otros lenguajes se edita el código.
