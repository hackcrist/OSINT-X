# Instalación

Requisitos verificados en manifiestos del repositorio.

---

## Especificación Técnica

| Lenguaje | Requisito | Arranque |
| :--- | :--- | :--- |
| Python | 3.10 o superior, sin paquetes externos | `cd src/python && python cli.py` |
| Go | 1.21 o superior | `cd src/go && go run .` o `go build -o osintx .` |
| JavaScript | Node 18 o superior, cero dependencias | `cd src/js && node cli.mjs` |
| Shell | Git Bash o Linux, `curl` y `jq` según módulo | `cd src/shell && ./osintx.sh` |

No se requiere clave de API para las fuentes incluidas. No hay variables de entorno en el código revisado.

---

## Consideraciones Críticas y Casos de Borde

1. **Red filtrada:** el DoH a `cloudflare-dns.com` puede fallar por interceptación TLS; el DNS del sistema sigue resolviendo.
2. **Puertos:** el escaneo solo debe dirigirse a objetivos propios o autorizados.
3. **Shell en Windows:** usar Git Bash, no CMD, por `jq` y sustituciones.

---

## Ejemplo de Uso

```bash
cd src/shell && ./osintx.sh 01 example.com
```
