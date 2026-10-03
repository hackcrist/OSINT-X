# OSINT-X

Consola modular de inteligencia pasiva en cuatro lenguajes: Python, Go, JavaScript y Shell. Nueve módulos aislados que consultan únicamente información pública y objetivos autorizados, con resultados estructurados que alimenta una capa común de reportes.

> Uso responsable: solo dominios e IPs propios o con autorización. Sin exploits, sin logins, sin fuerza bruta.

## Módulos

| Código | Módulo | Contenido |
|---|---|---|
| 01 | DOMAIN | DNS, registros MX/TXT/NS, IPs asociadas, WHOIS/RDAP |
| 02 | PORTSCAN | Puertos TCP, servicios, banners, versiones |
| 03 | SUBDOMAIN | Enumeración pasiva, transparencia de certificados, DNS, wordlists |
| 04 | PHONE | Formato, país, operador y metadatos públicos |
| 05 | USERNAME | Presencia pública en plataformas y enlaces |
| 06 | IPINFO | ASN, ISP y geolocalización aproximada |
| 07 | EMAIL | Verificación y metadatos públicos |
| 08 | URL | Análisis de enlaces |
| 09 | REPORT | Guarda el último resultado en JSON, TXT o HTML |
| 00 | EXIT | Salida |

## Inicio rápido

```bash
# Python (solo biblioteca estándar, 3.10+)
cd src/python
python cli.py

# Go (1.21+)
cd src/go
go run .          # o compilar: go build -o osintx .

# JavaScript (Node 18+, cero dependencias)
cd src/js
node cli.mjs

# Shell (Git Bash o Linux)
cd src/shell
./osintx.sh                 # menú
./osintx.sh 01 example.com  # atajo: módulo + objetivo
```

## Documentación

Manuales en `docs/`: [índice](docs/index.md), arquitectura, uso por lenguaje y referencia de módulos y errores.
