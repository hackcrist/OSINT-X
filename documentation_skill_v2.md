---
name: documentation-architecture
version: 2.0.0
status: stable
purpose: >
  Analizar repositorios de software y construir, reestructurar o mantener una documentación
  técnica de alta fidelidad, profesional y verificable, compatible con Ferrum Docs.
principles:
  - evidence-first
  - zero-hallucination
  - traceability
  - reproducibility
  - security-aware
  - maintainability
  - operational-readiness
---

# Guía de Habilidad: Arquitectura y Generación de Documentación Profesional

Esta skill define el protocolo para analizar un repositorio de software y construir, reestructurar o mantener una carpeta `docs/` de alta fidelidad técnica, compatible con Ferrum Docs.

El objetivo no es producir documentación extensa por sí misma. El objetivo es producir documentación **correcta, verificable, mantenible, navegable y útil para desarrollo, operación, auditoría y mantenimiento**.

---

## 1. Fase Previa Obligatoria: Consulta Interactiva

Antes de inspeccionar el código o redactar documentación, la IA debe formular estas preguntas y esperar respuesta, salvo que el usuario ya haya proporcionado explícitamente esos datos:

1. **Idioma:**
   > ¿En qué idioma deseas la documentación? (Ej. Español técnico, English, etc.)

2. **Profundidad:**
   > ¿Prefieres documentación corta/ágil o extensa/exhaustiva?

3. **Emojis:**
   > ¿Deseas señalización visual con emojis técnicos o un formato estrictamente sobrio?

Si el usuario ya indicó las tres preferencias, no volver a preguntarlas.

---

## 2. Principios de Calidad

### 2.1 Evidencia primero

Toda afirmación técnica relevante debe derivarse de una fuente verificable del proyecto:

- código fuente;
- manifiestos y archivos de configuración;
- tests;
- migraciones y esquemas;
- documentación existente;
- contratos de API;
- scripts de despliegue;
- infraestructura declarativa.

No inventar clases, funciones, endpoints, parámetros, comandos, rutas ni comportamientos.

### 2.2 Cero alucinaciones

Si una característica no puede comprobarse, debe marcarse como desconocida o no documentarse como hecho.

Nunca utilizar placeholders ficticios que parezcan datos reales, como `ERR_001`, `MyClass` o endpoints inventados, salvo que se indiquen explícitamente como ejemplos conceptuales y no como elementos del proyecto.

### 2.3 Trazabilidad

Cuando sea relevante, mantener la relación:

```text
Requisito → componente → archivo → símbolo → test → documentación
```

La documentación debe permitir localizar rápidamente dónde está implementado un comportamiento.

### 2.4 Reproducibilidad

Los comandos, ejemplos y procedimientos documentados deben poder reproducirse con el entorno y las dependencias declaradas por el proyecto.

### 2.5 Separación entre hecho e inferencia

Clasificar internamente la evidencia como:

- **VERIFIED:** comprobada directamente en el repositorio.
- **INFERRED:** deducida razonablemente a partir del código.
- **EXTERNAL:** procedente de una fuente externa autorizada.
- **UNKNOWN:** no comprobable con la información disponible.

No presentar una inferencia como hecho.

---

## 3. Prohibición de Metacomentarios

Los archivos generados no deben contener comentarios sobre esta skill, preferencias del usuario, configuración interna o proceso de generación.

Cada archivo Markdown debe comenzar directamente con su título formal:

```markdown
# Título
```

---

## 4. Política de Emojis

Si el usuario selecciona sin emojis, usar Markdown sobrio.

Si los permite, utilizar únicamente señalización técnica como:

`⚙️` `📦` `🔍` `⚠️` `💡` `📋`

No utilizar emojis decorativos o informales.

---

## 5. Niveles de Profundidad

### Documentación corta

Crear una estructura condensada de aproximadamente 3–5 documentos principales:

- visión general;
- instalación;
- arquitectura;
- referencia principal;
- diagnóstico.

### Documentación extensa

Construir una estructura completa donde cada subsistema crítico tenga documentación propia, incluyendo cuando corresponda:

- arquitectura;
- flujo de datos;
- contratos;
- configuración;
- seguridad;
- rendimiento;
- errores;
- operación;
- pruebas;
- API;
- despliegue.

---

## 6. Arquitectura Obligatoria de Ferrum Docs

La estructura máxima admitida es de dos niveles:

```text
docs/
├── index.md
├── 01-Arquitectura/
│   ├── index.md
│   ├── componentes.md
│   ├── flujo_datos.md
│   └── seguridad.md
├── 02-Guias/
│   ├── index.md
│   ├── instalacion.md
│   ├── configuracion.md
│   └── despliegue.md
├── 03-API/
│   ├── index.md
│   ├── endpoints.md
│   └── webhooks.md
└── 04-Referencia/
    ├── index.md
    ├── errores.md
    └── cli.md
```

### Reglas

1. No crear carpetas de nivel 3 o superior.
2. Cada sección debe tener `index.md`.
3. `docs/index.md` es obligatorio.
4. Todo `.md` debe comenzar con `# Título`.
5. Utilizar prefijos numéricos de dos dígitos.
6. Utilizar enlaces relativos válidos.
7. No colocar ejecutables ni scripts dentro de `docs/`.
8. Mantener el contenido dentro del límite operativo de Ferrum Docs.

---

## 7. Pipeline Profesional de Análisis

La IA debe seguir este orden lógico:

```text
[1 Manifiestos]
      ↓
[2 Inventario del repositorio]
      ↓
[3 Arquitectura]
      ↓
[4 Datos y configuración]
      ↓
[5 APIs / CLI]
      ↓
[6 Seguridad]
      ↓
[7 Tests]
      ↓
[8 Operaciones]
      ↓
[9 Errores y casos límite]
      ↓
[10 Trazabilidad]
      ↓
[11 Redacción]
      ↓
[12 Validación]
```

Nunca saltar directamente a la redacción cuando el repositorio aún no ha sido analizado.

---

## 8. Fase 1: Inventario del Repositorio

Identificar antes de redactar:

- lenguaje(s);
- framework(s);
- versión(es);
- gestores de dependencias;
- estructura de directorios;
- punto(s) de entrada;
- módulos principales;
- configuración;
- variables de entorno;
- bases de datos;
- servicios externos;
- APIs;
- CLI;
- tests;
- CI/CD;
- infraestructura.

Crear mentalmente un mapa del sistema antes de decidir la estructura final de documentación.

---

## 9. Fase 2: Arquitectura

Identificar:

- capas;
- componentes;
- responsabilidades;
- dependencias;
- flujo de datos;
- ciclo de vida;
- límites de cada módulo;
- puntos de integración;
- estado y persistencia;
- procesos síncronos y asíncronos.

Cuando la complejidad lo justifique, documentar modelos equivalentes a:

- contexto del sistema;
- contenedores/componentes;
- secuencia;
- despliegue.

No inventar diagramas. Todo nodo y relación debe poder justificarse mediante evidencia del proyecto.

---

## 10. Fase 3: Configuración y Datos

Documentar, cuando existan:

- variables de entorno;
- archivos de configuración;
- valores requeridos y opcionales;
- valores por defecto reales;
- secretos y cómo se suministran sin exponerlos;
- esquemas de base de datos;
- migraciones;
- relaciones;
- índices relevantes;
- colas;
- cachés;
- almacenamiento externo.

Nunca copiar secretos, tokens, claves privadas o credenciales reales a la documentación.

---

## 11. Fase 4: APIs y Contratos

Para cada API pública encontrada documentar, cuando exista:

| Elemento | Contenido |
|---|---|
| Método | HTTP/CLI/RPC/etc. |
| Ruta/comando | Valor real |
| Autenticación | Mecanismo real |
| Entrada | Parámetros/payload real |
| Validación | Reglas encontradas |
| Respuesta | Estructura real |
| Errores | Códigos/excepciones reales |
| Idempotencia | Si aplica |
| Paginación | Si aplica |
| Límites | Si están definidos |
| Versionado | Si existe |

Los ejemplos deben proceder del código, tests o contratos reales siempre que sea posible.

---

## 12. Fase 5: Seguridad

Cuando el proyecto maneje autenticación, autorización, datos sensibles, red, archivos, ejecución de comandos o servicios externos, realizar una revisión específica de:

- autenticación;
- autorización;
- gestión de sesiones/tokens;
- secretos;
- validación de entrada;
- sanitización;
- control de acceso;
- exposición de datos;
- almacenamiento sensible;
- dependencias críticas;
- superficies de ataque visibles en el código;
- logging de información sensible.

Documentar únicamente riesgos sustentados por evidencia.

No convertir esta sección en una auditoría de seguridad completa salvo que el usuario la solicite.

---

## 13. Fase 6: Tests y Calidad

Inspeccionar `tests/`, `test/`, `spec/` y equivalentes.

Registrar:

- framework de testing;
- suites existentes;
- áreas cubiertas;
- casos límite demostrados;
- fixtures relevantes;
- comandos reales de ejecución;
- cobertura si está disponible.

Los tests son una fuente prioritaria para ejemplos porque muestran comportamiento verificable.

---

## 14. Fase 7: Operación y Despliegue

Cuando exista información suficiente, documentar:

- requisitos del sistema;
- instalación;
- configuración;
- arranque;
- parada;
- actualización;
- migraciones;
- despliegue;
- rollback;
- backups;
- restauración;
- logs;
- métricas;
- health checks;
- tareas programadas;
- dependencias externas.

No inventar procedimientos operativos que no estén respaldados por el proyecto.

---

## 15. Fase 8: Errores y Diagnóstico

Buscar sistemáticamente:

- `throw`;
- `raise`;
- excepciones personalizadas;
- códigos HTTP;
- códigos de salida;
- mensajes de error;
- validaciones;
- timeouts;
- reintentos;
- circuit breakers;
- condiciones de fallo.

Crear una matriz cuando el volumen lo justifique:

| Código/Excepción | Subsistema | Condición | Causa | Tratamiento |
|---|---|---|---|---|

Solo incluir errores realmente existentes.

---

## 16. Rendimiento y Escalabilidad

Cuando exista evidencia suficiente, documentar:

- operaciones costosas;
- complejidad relevante;
- límites conocidos;
- concurrencia;
- memoria;
- CPU;
- I/O;
- caché;
- colas;
- paginación;
- timeouts;
- mecanismos de escalado.

No afirmar cifras de rendimiento sin mediciones o evidencia del proyecto.

---

## 17. Matriz de Trazabilidad

Para proyectos medianos o grandes, mantener una tabla de trazabilidad cuando sea útil:

| Área | Implementación | Test | Documento |
|---|---|---|---|
| Funcionalidad | Archivo/símbolo real | Test real | Documento real |

El objetivo es detectar rápidamente documentación sin implementación, implementación sin documentación y funcionalidades sin cobertura conocida.

---

## 18. Arquitectura de Documentos

### `docs/index.md`

Debe incluir:

- nombre y versión real del proyecto;
- propósito;
- arquitectura resumida;
- requisitos;
- inicio rápido verificado;
- mapa de documentación;
- referencias principales.

### `01-Arquitectura/index.md`

Debe explicar el modelo general del sistema y enlazar sus componentes.

### `02-Guias/index.md`

Debe reunir procedimientos reproducibles.

### `03-API/index.md`

Debe presentar los contratos públicos.

### `04-Referencia/index.md`

Debe reunir diagnóstico, CLI, configuración y referencias técnicas.

Las secciones pueden omitirse cuando no existan en el proyecto. No crear documentación artificial solo para llenar una estructura.

---

## 19. Reglas de Redacción Técnica

Cada documento debe:

1. comenzar con `# Título`;
2. explicar primero el propósito;
3. indicar el alcance;
4. usar terminología consistente;
5. separar conceptos de procedimientos;
6. utilizar tablas cuando mejoren precisión;
7. usar bloques de código para comandos y ejemplos;
8. evitar texto promocional;
9. evitar afirmaciones no verificadas;
10. enlazar documentos relacionados.

---

## 20. Control de Consistencia

Antes de finalizar, comparar la documentación nueva contra:

- código fuente;
- README;
- manifiestos;
- configuración;
- tests;
- contratos API;
- scripts de despliegue;
- documentación previa.

Si existen contradicciones, no elegir arbitrariamente una versión. Determinar cuál tiene evidencia más directa y señalar la discrepancia cuando sea relevante.

---

## 21. Validación Automática Final

Antes de considerar terminada la documentación, comprobar:

- [ ] `docs/index.md` existe.
- [ ] Cada sección tiene `index.md`.
- [ ] No existen carpetas de nivel 3.
- [ ] Cada Markdown comienza con `#`.
- [ ] Los enlaces internos son válidos.
- [ ] Las rutas de archivos citadas existen.
- [ ] Los símbolos documentados existen.
- [ ] Los comandos documentados coinciden con el proyecto.
- [ ] Los endpoints documentados existen.
- [ ] Los ejemplos no contienen APIs ficticias.
- [ ] No hay secretos expuestos.
- [ ] No hay scripts ejecutables prohibidos en `docs/`.
- [ ] No hay placeholders presentados como hechos.
- [ ] Las versiones coinciden con las fuentes disponibles.
- [ ] Los procedimientos principales son reproducibles.
- [ ] Las contradicciones relevantes fueron detectadas.
- [ ] La documentación refleja los tests disponibles.
- [ ] La documentación no afirma capacidades que el código no demuestra.

---

## 22. Detección de Documentación Desactualizada

Cuando se actualice un repositorio existente, comparar los documentos afectados contra la implementación actual.

Buscar especialmente:

- funciones eliminadas;
- clases renombradas;
- endpoints modificados;
- parámetros cambiados;
- comandos eliminados;
- variables de entorno nuevas o eliminadas;
- cambios de versión;
- cambios de arquitectura;
- migraciones nuevas;
- comportamiento que ya no coincide.

Si una sección quedó obsoleta, actualizarla o eliminarla en lugar de conservar información incorrecta.

---

## 23. Política de Cambios

Cuando la documentación se actualice por cambios del proyecto, registrar cuando corresponda:

- cambio funcional;
- cambio arquitectónico;
- cambio de API;
- breaking change;
- migración requerida;
- impacto operativo;
- compatibilidad.

No crear un changelog artificial si el proyecto no utiliza uno y el usuario no lo solicita.

---

## 24. Adaptación al Tipo de Proyecto

### Librerías / SDKs / Parsers

Priorizar:

- arquitectura interna;
- ciclo de procesamiento;
- API pública;
- tipos;
- extensiones;
- errores;
- ejemplos;
- compatibilidad.

### Aplicaciones Web / APIs

Priorizar:

- arquitectura por capas;
- autenticación;
- autorización;
- persistencia;
- endpoints;
- configuración;
- despliegue;
- observabilidad.

### CLI / Herramientas

Priorizar:

- instalación;
- comandos;
- opciones;
- códigos de salida;
- configuración;
- ejemplos;
- diagnóstico.

### Sistemas distribuidos

Priorizar:

- componentes;
- comunicación;
- eventos;
- colas;
- consistencia;
- fallos;
- reintentos;
- observabilidad;
- despliegue.

### Proyectos con infraestructura

Priorizar:

- topología;
- recursos;
- dependencias;
- configuración;
- secretos;
- despliegue;
- recuperación.

---

## 25. Manejo de Información Insuficiente

Si el repositorio no permite verificar una afirmación:

- no inventarla;
- no completar el hueco con una suposición presentada como hecho;
- indicar qué información falta;
- documentar únicamente lo verificable.

Si una fuente externa es necesaria y el usuario la permite, distinguir claramente la información externa de la evidencia del repositorio.

---

## 26. Compatibilidad y Límites de Ferrum Docs

Mantener las restricciones estructurales conocidas de Ferrum Docs:

- profundidad máxima de dos niveles;
- `docs/index.md` como entrada;
- `index.md` en cada sección;
- encabezado H1 en la primera línea;
- enlaces relativos;
- extensiones permitidas;
- ausencia de ejecutables y scripts peligrosos;
- tamaño razonable de la documentación.

No sacrificar estas reglas por una arquitectura documental más compleja.

---

## 27. Checklist de Cierre Profesional

### Estructura

- [ ] Navegación correcta.
- [ ] Jerarquía válida.
- [ ] Índices completos.
- [ ] Enlaces comprobados.

### Fidelidad

- [ ] Código revisado.
- [ ] Tests revisados.
- [ ] Configuración revisada.
- [ ] APIs verificadas.
- [ ] Errores verificados.

### Seguridad

- [ ] No existen secretos expuestos.
- [ ] Se revisaron mecanismos de autenticación/autorización cuando aplican.
- [ ] Se documentaron riesgos solo cuando existe evidencia.

### Operación

- [ ] Instalación verificable.
- [ ] Configuración documentada.
- [ ] Ejecución documentada.
- [ ] Despliegue documentado cuando corresponde.
- [ ] Recuperación documentada cuando existe soporte real.

### Mantenimiento

- [ ] Cambios importantes identificados.
- [ ] Información obsoleta eliminada.
- [ ] Contradicciones detectadas.
- [ ] Trazabilidad razonable.

### Calidad final

- [ ] Sin contenido inventado.
- [ ] Sin metacomentarios.
- [ ] Sin placeholders falsamente presentados como reales.
- [ ] Sin comandos no verificados.
- [ ] Sin rutas o símbolos inexistentes.
- [ ] Documentación coherente con el estado actual del repositorio.

---

## 28. Resultado Esperado

La salida final debe comportarse como una **fuente técnica confiable del proyecto**: navegable, verificable, reproducible y mantenible.

La calidad se mide por la fidelidad al software real, no por la cantidad de páginas generadas.
