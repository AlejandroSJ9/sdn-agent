# Debug: SDN Agent — Optimización del prompt de clasificación

## Contexto del proyecto

Sistema de detección de ransomware en redes SDN. El agente recibe alertas JSON
del controlador Ryu y usa un LLM (OpenRouter) para clasificarlas. El problema:
el agente clasifica casi todo como `confirmado` generando falsos positivos altos.

**Último reporte de calidad:**
- Accuracy: 57.9% | Precision: 55.6% | Recall: 100% | Tasa FP: 88.9%
- El modelo detecta todos los ataques reales pero no discrimina tráfico legítimo

## Archivos relevantes

```
services/prompt.py          ← el prompt actual (system prompt + user prompt)
services/llm.py             ← loop bidireccional con OpenRouter
test_agente_riguroso.py     ← suite de 20 casos con métricas
reporte_calidad_*.json      ← último reporte de pruebas
```

## Casos que fallan consistentemente

Los 8 casos fallidos tienen un patrón claro — el modelo dice `confirmado` cuando debería decir `falso_positivo` o `indeterminado`:

| ID | Caso | M3 | M5 | Puntaje | Esperado | Obtenido |
|----|------|----|----|---------|----------|---------|
| FP-01 | Backup nocturno | false | false | 45 | falso_positivo | confirmado |
| FP-02 | Nmap inventario | false | false | 45 | falso_positivo | confirmado |
| FP-03 | Transferencia archivos | false | false | 60 | falso_positivo | confirmado |
| FP-04 | Primera VPN | false | false | 60 | falso_positivo | confirmado |
| BD-01 | Puntaje límite 60pts | false | false | 60 | indeterminado | confirmado |
| BD-03 | M5 count=5 sin M3 | false | true/5 | 65 | indeterminado | confirmado |
| BD-04 | Puntaje 61pts | false | false | 61 | indeterminado | confirmado |
| YC-01 | Host ya bloqueado | true | true | 120 | ya_contenido | confirmado |

**Patrón común:** cuando M3=false y M5=false, el modelo ignora esa ausencia
y confirma el ataque basándose solo en M1+M2. Además nunca usa `ya_contenido`.

## Lo que ya se intentó sin éxito

1. Instrucciones rígidas tipo "si M3=false y M5=false → no confirmar" → sesgo inverso
2. Subir max_tokens de 2000 a 5000 → resolvió JSON truncado pero no la clasificación
3. Cambio de modelo a llama-3.1-8b-instruct:free → mejora parcial
4. Agregar ejemplos en el prompt → el modelo los sigue mecánicamente sin razonar

## Tu tarea

Analiza `services/prompt.py` completo y propón una versión mejorada que:

1. Resuelva los 8 casos fallidos sin romper los 11 que ya pasan
2. No caiga en sesgo inverso (el modelo empezó siendo demasiado conservador, luego demasiado agresivo)
3. Siga los principios modernos de prompt engineering: chain-of-thought, few-shot calibrado, instrucciones de calibración de confianza

**Restricciones:**
- El output del LLM debe seguir siendo JSON puro (sin markdown)
- No agregar más de 200 tokens al prompt actual — ya está en el límite de contexto útil
- El campo `razonamiento` en el JSON de respuesta debe mostrar el pensamiento real del modelo

## Hipótesis a investigar

Antes de reescribir, verifica en el código:

- ¿El `user_prompt` incluye las señales de contexto calculadas (M3=false, M5=false)?
  Busca en `construir_user_prompt()` la sección `=== SEÑALES DE CONTEXTO ===`
  
- ¿El campo `hosts_bloqueados` que llega al prompt incluye el host actual cuando
  se repite una alerta? Esto es clave para YC-01.
  Busca en `db/repository.py` → `get_hosts_bloqueados()`

- ¿Cuántos tokens tiene el system prompt actual?
  `len(SYSTEM_PROMPT.split())` — si supera 1500 palabras el modelo empieza a ignorar
  las instrucciones del final (lost in the middle problem)

## Entregable esperado

Un `prompt.py` modificado con:
- System prompt optimizado (máximo 1200 palabras)
- `construir_user_prompt()` que calcule y exponga mejor las señales de contexto
- 2-3 ejemplos few-shot calibrados: uno confirmado, uno falso_positivo, uno indeterminado
- Explicación de cada cambio y por qué debería resolver los casos fallidos
