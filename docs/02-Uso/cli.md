# CLI por Lenguaje

Contrato de línea de comandos de cada implementación.

---

## Especificación Técnica

### Python

```bash
cd src/python
python cli.py            # menú 01-09, 00 sale
```

Acepta `1`-`9` o `01`-`09`. La opción `09` pide formato (`json`, `txt`, `html`) y carpeta (defecto `reports/`).

### Go

```bash
cd src/go
go run .                 # menú 01-09
go build -o osintx.exe .
```

Acepta `1`-`9` o `01`-`09`. Salida JSON por stdout.

### JavaScript

```bash
cd src/js
node cli.mjs             # menú 01-09
```

Acepta `1`-`9` o `01`-`09`.

### Shell

```bash
cd src/shell
./osintx.sh              # menú 01-09, 00 sale
./osintx.sh 01 example.com   # atajo: módulo + objetivo
./osintx.sh 06 8.8.8.8       # atajo: IPINFO directo
```

Acepta `1`-`9` o `01`-`09`.

---

## Consideraciones Críticas y Casos de Borde

1. **Sin banderas `--version`:** ninguna implementación expone versión por CLI; la versión vive en `package.json` (JS, 1.0.0) y `OSINTX_VERSION` (Shell, 1.0.0).
2. **Ctrl-C:** Python vuelve al menú; en Shell termina el script.
3. **EOF (pipe cerrado):** Shell y Go terminan; Python repite el menú (defecto conocido, pendiente de decisión).
