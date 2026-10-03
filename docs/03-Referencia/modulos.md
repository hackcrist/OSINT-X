# Módulos 01-09

Contrato operativo de cada módulo. Entrada típica, fuentes públicas y forma de salida. Verificado contra el código de `src/`.

---

## Especificación Técnica

| Código | Entrada | Fuentes | Salida |
| :--- | :--- | :--- | :--- |
| 01 DOMAIN | dominio | DNS del sistema, DoH, RDAP (`rdap.org`) | A/AAAA, MX, TXT, NS, IPs, RDAP |
| 02 PORTSCAN | host autorizado, puertos | Sockets TCP con timeout | Puertos, servicios, banners, versiones |
| 03 SUBDOMAIN | dominio | Transparencia de certificados, DNS, wordlists | Lista de subdominios |
| 04 PHONE | teléfono `+país` | Formato, metadatos públicos | País, operador si hay fuente |
| 05 USERNAME | nombre | Perfiles públicos por plataforma | Presencia y enlaces |
| 06 IPINFO | IP | GeoIP, ASN, ISP | País, red, proveedor |
| 07 EMAIL | correo | Sintaxis y metadatos públicos | Validez y datos |
| 08 URL | URL | Cabeceras y contenido público | Análisis del enlace |
| 09 REPORT | último resultado | — | Archivo JSON, TXT o HTML |
| 00 EXIT | — | — | Cierre limpio |

Toda salida incluye estado (`ok`, `partial`, `error`), lista de fuentes y hora de obtención. Lo no observado se reporta como error explícito, nunca como dato inventado.

---

## Consideraciones Críticas y Casos de Borde

1. **Puertos y teléfonos:** usar solo objetivos propios o autorizados.
2. **Estimaciones:** ASN, operador y geolocalización son aproximados según la fuente.
3. **Sitios con login:** la presencia en plataformas con muro puede requerir verificación manual.
