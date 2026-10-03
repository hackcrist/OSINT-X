# Catálogo de Diagnósticos y Errores

Condiciones de error observadas en ejecución real, con causa y resolución.

---

## Matriz de Errores

| Código | Nivel | Subsistema | Causa Raíz | Solución Técnica |
| :--- | :--- | :--- | :--- | :--- |
| `CERTIFICATE_VERIFY_FAILED` en DoH | Error | 01 DOMAIN (Python/JS) | Red con filtro TLS que intercepta `cloudflare-dns.com` | Usar DNS del sistema; migrar DoH a endpoint verificable |
| `status=partial` sin registros DoH | Aviso | 01 DOMAIN | Respaldo DoH caído, sistema resolvió | Revisar `ips_observed`; nada que corregir |
| `sin RDAP` | Aviso | 01 DOMAIN | Registro sin RDAP o `rdap.org` caído | Reintentar; no es falla del módulo |
| `puerto filtrado/silencio` | Informativo | 02 PORTSCAN | Firewall descarta sin responder | Reportar como filtrado, no como cerrado |
| `sitio bloquea bots (403/429)` | Aviso | 05 USERNAME | Protección anti-automatización | Marcar como indicio y verificar a mano |
| `sin PTR` | Informativo | IP/DNS | Dueño sin reverso creado | Normal en móviles y nubes |
| `módulo Go sin comando` | Error | CLI Go | Subcomando inexistente | Usar menú 01-09 o `00` para salir |
| `reports/ ausente` | Informativo | 09 REPORT | Primera ejecución | La capa de reporte crea la carpeta al guardar |
