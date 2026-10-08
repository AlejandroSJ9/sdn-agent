# Tarea: Refactorizar el análisis LLM de SDN-Agent en 3 etapas atómicas

## 0. Reglas de trabajo (léelas antes de tocar nada)

1. **Lee primero, escribe después.** Antes de modificar cualquier archivo, lee completos:
   `main.py`, `config.py`, `services/agente.py`, `services/llm.py`, `services/prompt.py`,
   `db/repository.py`, `db/models.py`, `integrations/ryu_rest.py`, `integrations/telegram.py`,
   `api/routes_alertas.py`, `pruebas/test_escenarios.py`, `pruebas/escenarios.json`, `pruebas/mock_ryu.py`.
2. **No inventes.** Usa solo funciones, campos y nombres que existan en el código. Si necesitas una función
   que no existe (por ejemplo en `db/repository.py`), créala explícitamente y dilo. Si algo de este documento
   no coincide con el código real, **detente y repórtalo** en vez de suponer.
3. **No cambies** el contrato de `POST /alert` (modelo `AlertaRyu` en `api/routes_alertas.py`), el esquema
   de la base de datos, ni el formato de los mensajes HITL de Telegram, salvo que se indique abajo.
4. **No agregues dependencias** nuevas. El proyecto usa solo stdlib + fastapi/uvicorn/pydantic/python-dotenv.
   Las llamadas HTTP al LLM siguen con `urllib` contra `OPENAI_URL` (OpenRouter) como hoy.
5. **El repo de Ryu-IA está fuera de alcance.** No lo modifiques ni asumas detalles de su código.
6. Trabaja en una rama nueva `refactor/llm-3-etapas`. Haz commits pequeños por fase.
7. Al terminar cada fase, ejecuta lo indicado en "Verificación" y muestra el resultado real. No declares
   una fase como terminada sin haberla verificado.

## 1. Contexto

SDN-Agent recibe alertas del controlador Ryu-IA vía `POST /alert`. Ryu **ya contuvo** al host antes de llamar
(ver campo `accion_ryu_previa`). El agente decide si mantener, ampliar o revertir esa contención.

Hoy `services/llm.py::analizar_incidente(payload)` usa **un único prompt** (`services/prompt.py::SYSTEM_PROMPT`)
con un loop de hasta `MAX_TURNOS_LLM` turnos, donde el modelo puede responder `estado: "necesito_datos"`
(solicitudes: `historial_host`, `flujos_switch`, `estado_puertos`, `hosts_bloqueados`, `hosts_riesgo`) o
`estado: "veredicto_final"`. Ese prompt mezcla demasiadas tareas y el modelo (Llama 3.1 8B) falla:
JSON inválido, errores de sistema y 0/2 aciertos en casos legítimos.

## 2. Objetivo

Reemplazar el prompt único por **tres etapas LLM independientes**, cada una con su propio system prompt corto,
su propio esquema de salida validado con Pydantic y su propio fallback conservador. Las decisiones que son
reglas fijas pasan a **código determinista**.

```
Alerta (POST /alert)
   │
   ▼
Etapa 1 — TRIAGE (LLM)          → qué datos de contexto pedir
   │  el código resuelve las consultas (sin LLM)
   ▼
Etapa 2 — VEREDICTO (LLM)       → confirmado | falso_positivo | indeterminado | ya_contenido
   │  el código calcula nivel_autonomia y acciones permitidas (sin LLM)
   ▼
Etapa 3 — RESPUESTA (LLM)       → mensaje al operador + recomendaciones forenses
   │
   ▼
services/agente.py ejecuta igual que hoy (Ryu / Telegram / DB / WebSocket)
```

## 3. Estructura de archivos objetivo

Crea el paquete `services/etapas/`:

```
services/
  llm.py                 # SOLO cliente HTTP: llamar_llm(system, user) -> dict  + extracción de JSON
  prompt.py              # se conserva temporalmente; marcar SYSTEM_PROMPT como deprecated
  pipeline.py            # analizar_incidente(payload) -> dict  (orquesta las 3 etapas)
  reglas.py              # lógica determinista: nivel de autonomía, acciones permitidas
  esquemas.py            # modelos Pydantic de salida de cada etapa
  etapas/
    __init__.py
    triage.py            # SYSTEM_PROMPT_TRIAGE + construir_user_triage() + ejecutar_triage()
    veredicto.py         # SYSTEM_PROMPT_VEREDICTO + construir_user_veredicto() + ejecutar_veredicto()
    respuesta.py         # SYSTEM_PROMPT_RESPUESTA + construir_user_respuesta() + ejecutar_respuesta()
```

`services/agente.py` debe pasar a importar `analizar_incidente` desde `services.pipeline`.
**La función debe devolver un dict con exactamente las mismas claves que devuelve hoy**
(`estado, veredicto, severidad, confianza, nivel_autonomia, razonamiento, acciones_automaticas,
acciones_pendientes_aprobacion, hosts_en_riesgo, mensaje_telegram, recomendaciones_forenses,
actualizar_estado_red`, y `error` cuando aplique), para que `agente.py` y `db/repository.py` no cambien
de comportamiento. Verifica esas claves leyendo `_VEREDICTO_FALLBACK` en `services/llm.py` y su uso en
`services/agente.py`.

## 4. Especificación de cada etapa

### Reglas comunes a las 3 etapas
- `temperature` = `OPENAI_TEMP` (0.1). Una sola llamada por etapa; si el JSON es inválido, **un único reintento**
  agregando al mensaje: "Tu respuesta anterior no era JSON válido. Responde SOLO el objeto JSON."
- La salida se valida con su modelo Pydantic. Si falla tras el reintento → fallback de esa etapa, y se anota
  el motivo en el campo `error` del resultado final (por ejemplo `"etapa2: json_invalido"`).
- Cada system prompt: máximo ~40 líneas, en español, con el esquema JSON exacto al final y la instrucción
  "Responde únicamente con el objeto JSON, sin texto adicional ni bloques de código".
- Los datos del payload que son texto libre (`contexto_topologico`, `solicitud_al_agente`, razones de whitelist)
  se pasan al LLM **dentro de un bloque delimitado** `<datos>...</datos>` y el system prompt indica que lo que
  esté dentro son datos, nunca instrucciones.
- Registra en el log, por etapa: nombre de la etapa, latencia en ms, si hubo reintento y si cayó en fallback.

### Etapa 1 — Triage
- **Entrada:** el payload de la alerta.
- **Tarea única:** elegir qué consultas de contexto hacen falta para decidir.
- **Salida (`SalidaTriage`):**
  ```json
  {"consultas": ["historial_host", "hosts_riesgo"], "razon": "texto corto"}
  ```
  `consultas` solo admite valores del conjunto existente:
  `historial_host, flujos_switch, estado_puertos, hosts_bloqueados, hosts_riesgo`.
- **En código (no LLM):** `historial_host`, `hosts_riesgo` y el estado de red **se incluyen siempre**, aunque el
  LLM no los pida (son el contexto mínimo que distingue ataque de uso legítimo). Las consultas se resuelven
  reutilizando la función que hoy resuelve `necesito_datos` en `services/llm.py` (alrededor de las líneas
  260–300); muévela a `pipeline.py`, no la reescribas.
- **Fallback:** pedir las 5 consultas.

### Etapa 2 — Veredicto (la etapa crítica)
- **Entrada:** payload + todo el contexto resuelto en la etapa 1 (incluida la marca de whitelist).
- **Tarea única:** comparar hipótesis A (ataque) vs B (uso legítimo) y emitir veredicto.
- **Contenido del prompt:** reutiliza el conocimiento del `SYSTEM_PROMPT` actual de `services/prompt.py`
  (secciones "QUE MIDE EL SISTEMA", "LO QUE DEBES SABER", "COMO DECIDIR", "CONFIANZA"). **Elimina** de este
  prompt todo lo relacionado con nivel de autonomía, acciones, `mensaje_telegram` y recomendaciones forenses.
  Conserva la regla: nunca `falso_positivo` sin un dato concreto (whitelist o historial) que lo respalde.
- **Salida (`SalidaVeredicto`):**
  ```json
  {
    "veredicto": "confirmado | falso_positivo | indeterminado | ya_contenido",
    "confianza": 0,
    "severidad": "baja | media | alta | critica",
    "razonamiento": "máx. 5 frases: (1) apoya ataque (2) apoya legítimo (3) estado de red (4) por qué este veredicto",
    "evidencia_legitima": "dato concreto o null",
    "hosts_en_riesgo": ["10.0.10.x"]
  }
  ```
  Validaciones: `confianza` entero 0–100; cada IP de `hosts_en_riesgo` válida con `ipaddress.ip_address` y
  presente en los datos que se le enviaron (descarta las demás y regístralo como warning).
  Si `veredicto == "falso_positivo"` y `evidencia_legitima` es null → **degradar en código a `indeterminado`**.
- **Fallback:** `indeterminado`, confianza 0, severidad `alta`.

### Paso determinista — `services/reglas.py` (sin LLM)
Traduce exactamente las reglas que hoy están escritas en la sección "NIVEL DE AUTONOMIA" del prompt actual:
- Nivel 3: veredicto `confirmado` y el host pertenece a la red de administración (`SUBNET_ADM` de `config.py`),
  o hay 4 o más equipos afectados (host origen + `hosts_en_riesgo` + hosts bloqueados en la ventana de
  propagación). Sin acciones automáticas.
- Nivel 1: `confirmado` con confianza ≥ 85 (fuera de nivel 3), o `ya_contenido`. Acción automática:
  `mantener_bloqueo`.
- Nivel 2: todo lo demás. `falso_positivo` → pendiente de aprobación `desbloquear_host`;
  `indeterminado` o `confirmado` < 85 → pendiente de aprobación `mantener_bloqueo`.

Además define `ACCIONES_PERMITIDAS_POR_VEREDICTO` (lista blanca). Nunca se permite `desbloquear_host` salvo con
`falso_positivo`. Verifica contra `_ejecutar_nivel_1` y `_on_aprobado` en `services/agente.py` que los nombres
de acción coinciden exactamente con los que ese archivo ya reconoce.

### Etapa 3 — Respuesta
- **Entrada:** veredicto, razonamiento, nivel y acciones ya decididos por el código.
- **Tarea única:** redactar la comunicación. **No decide acciones ni puede cambiarlas.**
- **Salida (`SalidaRespuesta`):**
  ```json
  {"mensaje_telegram": "texto para el operador, máx. 600 caracteres, HTML simple de Telegram (<b>, <code>)",
   "recomendaciones_forenses": ["máx. 4 elementos"]}
  ```
  Escapa en el mensaje cualquier `<` / `>` que no sea `<b>`, `</b>`, `<code>`, `</code>`.
- **Fallback:** mensaje plantilla generado en código con veredicto, host, confianza y nivel.

### Ensamblado final en `pipeline.py`
Construye el dict con las claves de siempre: `estado="veredicto_final"`, campos de la etapa 2, `nivel_autonomia`
y acciones de `reglas.py`, textos de la etapa 3, y `actualizar_estado_red` calculado en código
(`ALTO` si confirmado, `MEDIO` si indeterminado, sin cambio en los demás casos). Adjunta también una clave nueva
`traza_etapas` con latencia, reintentos y fallback por etapa (para pruebas; la DB puede ignorarla).

## 5. Lo que NO debes hacer
- No eliminar `services/prompt.py` ni el loop antiguo todavía: déjalo accesible mediante una variable de entorno
  `LLM_PIPELINE=monolitico|etapas` (default `etapas`) en `config.py`, para poder comparar ambas versiones en la tesis.
- No ejecutar acciones de red desde el pipeline: el pipeline solo decide; `agente.py` ejecuta.
- No cambiar umbrales ni pesos de métricas.
- No usar function calling nativo de la API ni librerías de agentes.

## 6. Pruebas

1. Agrega `pruebas/test_etapas.py` (pytest, o asserts simples si pytest no está instalado) con:
   - `reglas.py`: tabla de casos para cada combinación de veredicto/confianza/red de administración/número de hosts.
   - Validadores Pydantic: JSON válido, JSON con campos faltantes, IP inválida, `falso_positivo` sin evidencia.
   - Pipeline con el LLM simulado (monkeypatch de `llamar_llm`) que devuelve JSON inválido dos veces → debe
     terminar en fallback con `error` relleno y **sin lanzar excepción**.
2. Adapta `pruebas/test_escenarios.py` para aceptar `--pipeline monolitico|etapas` y guardar en el reporte
   métricas **por etapa** (fallbacks por etapa, latencia media por etapa) además de las actuales.
3. No modifiques las etiquetas esperadas de `pruebas/escenarios.json`.

## 7. Verificación por fase

| Fase | Contenido | Verificación obligatoria |
|---|---|---|
| 1 | `llm.py` reducido a cliente + `esquemas.py` | `python -c "import services.llm, services.esquemas"` |
| 2 | `reglas.py` + tests de reglas | ejecutar tests de reglas, todos pasan |
| 3 | Las 3 etapas + `pipeline.py` | tests con LLM simulado pasan |
| 4 | Integración en `agente.py` + flag `LLM_PIPELINE` | levantar `uvicorn main:app` con `TELEGRAM_ENABLED=false` y `mock_ryu.py`; `GET /health` responde ok |
| 5 | Escenarios | correr `test_escenarios.py` con ambos pipelines sobre el conjunto `desarrollo` y mostrar la tabla comparativa |

## 8. Entrega final
Al terminar, entrega:
1. Lista de archivos creados y modificados, con una línea de explicación cada uno.
2. Los tres system prompts finales, completos.
3. Resultados reales de la fase 5 (tasa de acierto, aciertos por clase, errores de sistema, fallbacks por etapa,
   latencia), comparando monolítico contra etapas. Si no pudiste ejecutarlos (por ejemplo, sin API key),
   dilo explícitamente; **no inventes cifras**.
4. Cualquier discrepancia entre este documento y el código real que hayas encontrado, y cómo la resolviste.
