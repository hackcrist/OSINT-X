# OSINT-X · Shell (Git Bash Windows + Linux)

Solo herramientas del sistema: `curl`, `dig`/`nslookup`, `openssl`,
`nc`/`timeout`, `getent`/`host`. Sin dependencias extra (no `jq`).

## Uso

```bash
./osintx.sh                 # menú 01-09 + 00 EXIT
./osintx.sh 01 example.com  # atajo: <módulo> <objetivo>
./modules/phone.sh "+34123456789"
./modules/domain.sh example.com | ./modules/report.sh DOMAIN example.com
```

## Contrato de salida

- `[OK] <modulo>: <dato>` — resultado
- `[INFO] ...` — progreso / dato indeterminado
- `[ERROR] ...` (stderr, `exit != 0`) — error explícito

`lib/common.sh` expone: `json_escape`, `timestamp_utc`, `http_get`
(`curl -sS -m 10 -A OSINT-X`), `http_headers`, `http_code`
(`curl -o /dev/null -w %{http_code}`), `print_header`,
`validate_*`, `dns_lookup` (dig→nslookup), `doh_lookup` (Cloudflare DoH).

## Módulos

| Nº | Script | Fuentes públicas |
|----|--------|------------------|
| 01 | `modules/domain.sh` | dig/nslookup + RDAP + DoH Cloudflare |
| 02 | `modules/portscan.sh` | timeout+/dev/tcp o nc, fallback curl (solo autorizados) |
| 03 | `modules/subdomain.sh` | crt.sh (Certificate Transparency) |
| 04 | `modules/phone.sh` | normalización E.164 + tabla de prefijos (aprox.) |
| 05 | `modules/username.sh` | perfiles públicos, clasifica por HTTP code |
| 06 | `modules/ipinfo.sh` | ip-api.com + reverse DNS (getent/host/nslookup) |
| 07 | `modules/email.sh` | MX/TXT-SPF + RDAP (sin brechas sin API key) |
| 08 | `modules/url.sh` | `curl -sSI` + heurística + `openssl s_client` |
| 09 | `modules/report.sh` | guarda JSON/TXT/HTML en `./reports/` |

## Reglas

Solo información pública, todo con timeout (`OSINTX_TIMEOUT`, defecto 10 s),
sin bypass, errores explícitos, salida estructurada simple.
