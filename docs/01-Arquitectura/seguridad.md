# Seguridad

Modelo de seguridad del sistema: qué hace y qué límites respeta, con evidencia del código.

---

## Especificación Técnica

| Control | Implementación |
| :--- | :--- |
| Solo lectura | Módulos GET y consultas DNS; sin escritura salvo `reports/` |
| Validación de entrada | Regex de dominio en Python (`validate_domain`), Go (`isValidDomain`) y JS (`normalizeDomain`); Shell valida por módulo |
| Sin secretos | No hay claves, tokens ni credenciales en el código; `OSINTX_UA` es solo User-Agent |
| Timeouts | Toda red con límite (5 a 15 segundos según lenguaje) |
| Salida contenida | `raw_truncated` limita cuerpos a 4000 caracteres en Python |
| Confirmación | El escaneo de puertos exige objetivo autorizado |

---

## Consideraciones Críticas y Casos de Borde

1. **Puertos:** dirigir el módulo 02 solo a hosts propios o autorizados.
2. **Curl restringido:** el helper Shell fuerza `--proto '=http,https'` para evitar otros esquemas.
3. **Datos personales:** los módulos devuelven lo público; lo no observado se reporta como ausente.
