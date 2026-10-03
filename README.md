# OSINT-X

Modular passive-intelligence console (Python + Go + Shell + JavaScript).

## Modules

- 01 DOMAIN
- 02 PORTSCAN
- 03 SUBDOMAIN
- 04 PHONE
- 05 USERNAME
- 06 IPINFO
- 07 EMAIL
- 08 URL
- 09 REPORT
- 00 EXIT

The project is designed around public information and authorized security testing.
Each module is isolated so results can be consumed by the report layer without
mixing implementation responsibilities.

## Implementations (`src/`)

All four share the same output contract:
`status / target / data / sources / retrieved_at / errors`.

- `src/python/` — `python src/python/cli.py` (stdlib only)
- `src/go/` — `cd src/go && go run .` (stdlib only)
- `src/shell/` — `bash src/shell/osintx.sh` (curl/dig/openssl)
- `src/js/` — `cd src/js && node cli.mjs` (Node 18+, sin dependencias)

Docs por skill siguen en `01-DOMAIN/` … `09-REPORT/*/SKILL.md`.
