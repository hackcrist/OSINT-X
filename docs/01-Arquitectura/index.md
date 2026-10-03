# Arquitectura

Capas del sistema, flujo de datos y ciclo de vida de una consulta en las cuatro implementaciones.

---

## Módulos y Especificaciones

* **[Componentes](componentes.md):** archivos fuente y símbolos por lenguaje.
* **[Flujo de datos](flujo_datos.md):** recorrido, tiempos y límites.
* **[Seguridad](seguridad.md):** controles y límites del sistema.

---

## Flujo de Trabajo

```
Entrada (dominio/IP/usuario/teléfono/URL)
  → Validación y normalización
    → Consultas públicas con timeout (DNS, RDAP, APIs sin clave, sockets)
      → Normalización a {status, target, data, sources, errors, retrieved_at}
        → Pantalla / capa REPORT (JSON, TXT, HTML)
```

Cada módulo aísla su responsabilidad y devuelve errores explícitos por consulta fallida en vez de resultados inventados. El estado global es `ok` con datos completos, `partial` con datos incompletos y `error` sin datos.
