"""
services/llm.py
Toda la comunicacion con OpenAI vive aqui.
Implementa el loop bidireccional (ReAct) con hasta MAX_TURNOS_LLM solicitudes
de datos adicionales antes de emitir el veredicto final.
"""

import json
import re
import logging
import urllib.request
import urllib.error
from typing import Any

from config import (
    OPENAI_API_KEY, OPENAI_MODEL, OPENAI_TEMP,
    OPENAI_MAX_TOKENS, OPENAI_URL, OPENAI_TIMEOUT,
    MAX_TURNOS_LLM,
)
from services.prompt import (
    get_system_prompt,
    construir_user_prompt,
    construir_mensaje_datos,
)
from db.repository import (
    get_historial_host,
    get_hosts_bloqueados,
    get_hosts_riesgo,
    get_estado_red,
    esta_en_whitelist,
)
from integrations.ryu_rest import get_flujos, get_puertos

logger = logging.getLogger('AgenteSDN.llm')

# Veredicto conservador que se retorna si algo falla
_VEREDICTO_FALLBACK = {
    'estado':                          'veredicto_final',
    'veredicto':                       'indeterminado',
    'severidad':                       'alta',
    'confianza':                       0,
    'nivel_autonomia':                 2,
    'razonamiento':                    'Fallback conservador - revisar logs.',
    'acciones_automaticas':            ['mantener_bloqueo'],
    'acciones_pendientes_aprobacion':  [],
    'hosts_en_riesgo':                 [],
    'mensaje_telegram':                '[AVISO] Incidente sin veredicto - revisar manualmente.',
    'recomendaciones_forenses':        ['Revisar manualmente el incidente'],
    'actualizar_estado_red':           {'nivel_alerta_red': 'ALTO'},
}


# ===============================================================================
# Llamada HTTP a OpenAI
# ===============================================================================

def _llamar_openai(messages: list[dict]) -> dict:
    """
    Llama a la API de OpenAI y retorna la respuesta parseada como dict.
    Lanza excepcion si la llamada falla - el caller decide como manejarlo.
    """
    body = json.dumps({
        'model':       OPENAI_MODEL,
        'messages':    messages,
        'temperature': OPENAI_TEMP,
        'max_tokens':  OPENAI_MAX_TOKENS,
    }).encode('utf-8')

    req = urllib.request.Request(
        OPENAI_URL,
        data=body,
        headers={
            'Content-Type':  'application/json',
            'Authorization': f'Bearer {OPENAI_API_KEY}',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT) as resp:
        data = json.loads(resp.read())

    raw = data['choices'][0]['message']['content'].strip()
    logger.debug(f'[LLM] Raw response ({len(raw)} chars): {raw[:200]}')

    # Intentar parsear JSON directamente
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # El modelo agrego texto extra - extraer solo el JSON
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f'No se pudo parsear JSON del LLM: {raw[:300]}')


# ===============================================================================
# Resolucion de solicitudes de datos del LLM
# ===============================================================================

def _resolver_solicitud(solicitud: str, parametros: dict) -> dict:
    """
    Obtiene los datos que el LLM solicito.
    Cada tipo de solicitud mapea a una funcion de repository o integration.
    """
    if solicitud == 'historial_host':
        ip = parametros.get('ip', '')
        historial = get_historial_host(ip)
        return {
            'ip':                 ip,
            'incidentes_previos': len(historial),
            'primer_incidente':   len(historial) == 0,
            'en_whitelist':       esta_en_whitelist(ip),
            'historial':          historial,
        }
    elif solicitud == 'flujos_switch':
        dpid = parametros.get('dpid', 1)
        return {'dpid': dpid, 'flujos': get_flujos(dpid)}
    elif solicitud == 'estado_puertos':
        dpid = parametros.get('dpid', 1)
        return {'dpid': dpid, 'puertos': get_puertos(dpid)}
    elif solicitud == 'hosts_bloqueados':
        return {'hosts': get_hosts_bloqueados()}
    elif solicitud == 'hosts_riesgo':
        return {'hosts': get_hosts_riesgo()}
    else:
        return {'error': f'Solicitud desconocida: {solicitud}'}


# ===============================================================================
# Loop bidireccional principal
# ===============================================================================

def analizar_incidente(payload: dict) -> dict:
    """
    Funcion principal de este modulo.
    Implementa el loop ReAct con el LLM:
      1. Construye el prompt con el contexto actual de la red
      2. Llama al LLM
    3. Si pide datos -> los obtiene y vuelve a llamar (max. MAX_TURNOS_LLM veces)
    4. Cuando da el veredicto final -> lo retorna
    5. Si algo falla -> retorna el veredicto fallback conservador
    """
    # Cargar contexto de la red
    estado_red       = get_estado_red()
    hosts_bloqueados = get_hosts_bloqueados()
    hosts_riesgo     = get_hosts_riesgo()

    # Construir prompt inicial
    user_prompt = construir_user_prompt(
        payload, estado_red, hosts_bloqueados, hosts_riesgo
    )
    messages = [
        {'role': 'system', 'content': get_system_prompt()},
        {'role': 'user',   'content': user_prompt},
    ]

    for turno in range(MAX_TURNOS_LLM):
        logger.info(f'[LLM] Turno {turno + 1}/{MAX_TURNOS_LLM} - '
                    f'host: {payload.get("host_origen")}')
        try:
            respuesta = _llamar_openai(messages)
        except urllib.error.URLError as e:
            logger.error(f'[LLM] Error de conexion con OpenAI: {e}')
            return _VEREDICTO_FALLBACK
        except ValueError as e:
            logger.error(f'[LLM] Error parseando respuesta: {e}')
            return _VEREDICTO_FALLBACK
        except Exception as e:
            logger.error(f'[LLM] Error inesperado: {e}')
            return _VEREDICTO_FALLBACK

        estado_respuesta = respuesta.get('estado')

        # -- El LLM pide mas datos ----------------------------------------------
        if estado_respuesta == 'necesito_datos':
            solicitud  = respuesta.get('solicitud', '')
            parametros = respuesta.get('parametros', {})
            razon      = respuesta.get('razon', '')
            logger.info(f'[LLM] Solicita: {solicitud} - {razon}')

            datos   = _resolver_solicitud(solicitud, parametros)
            msg_datos = construir_mensaje_datos(solicitud, datos)

            messages.append({'role': 'assistant', 'content': json.dumps(respuesta)})
            messages.append({'role': 'user',      'content': msg_datos})

        # -- El LLM da el veredicto final ---------------------------------------
        elif estado_respuesta == 'veredicto_final':
            logger.info(
                f'[LLM] Veredicto en turno {turno + 1}: '
                f'{respuesta.get("veredicto")} '
                f'(confianza: {respuesta.get("confianza")}%)'
            )
            return respuesta

        # -- Respuesta sin campo "estado" - asumir veredicto ------------------
        else:
            logger.warning(
                f'[LLM] Respuesta sin campo "estado" en turno {turno + 1} '
                f'- asumiendo veredicto final'
            )
            respuesta['estado'] = 'veredicto_final'
            return respuesta

    # Limite de turnos alcanzado sin veredicto
    logger.warning(
        f'[LLM] Limite de {MAX_TURNOS_LLM} turnos alcanzado '
        f'para {payload.get("host_origen")} - retornando fallback'
    )
    return _VEREDICTO_FALLBACK