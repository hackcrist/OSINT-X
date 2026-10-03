# OSINT-X

Consola modular de inteligencia pasiva en Python, Go, JavaScript y Shell. Nueve módulos aislados sobre información pública, con capa común de reportes en JSON, TXT y HTML.

---

## Arquitectura del Sistema

Cuatro implementaciones independientes consumen las mismas fuentes públicas y devuelven resultados estructurados con estado (`ok`, `partial`, `error`), fuentes y hora de obtención.

---

## Mapa de Documentación

### 1. Arquitectura
* **[General](01-Arquitectura/index.md):** capas, flujo y ciclo de ejecución.
* **[Componentes](01-Arquitectura/componentes.md):** archivos y funciones por lenguaje.

### 2. Uso
* **[General](02-Uso/index.md):** menús, atajos y salidas.
* **[Instalación](02-Uso/instalacion.md):** requisitos por lenguaje.

### 3. Referencia
* **[General](03-Referencia/index.md):** módulos, códigos y diagnóstico.
* **[Módulos](03-Referencia/modulos.md):** contrato de cada módulo 01-09.
* **[Errores](03-Referencia/errores.md):** fallos conocidos y resolución.

---

## Inicio Rápido

```bash
cd src/python && python cli.py
cd src/go && go run .
cd src/js && node cli.mjs
cd src/shell && ./osintx.sh 01 example.com
```
