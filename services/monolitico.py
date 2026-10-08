# -*- coding: utf-8 -*-
"""
services/monolitico.py
Analisis con el prompt unico (services/prompt.py::SYSTEM_PROMPT) y loop
ReAct de hasta MAX_TURNOS_LLM turnos. Es el analizador anterior a las
3 etapas; se conserva para compararlo en la tesis (LLM_PIPELINE=monolitico).
"""

import json
import logging
import urllib.error

from config import OPENAI_MODEL, MAX_TURNOS_LLM
from services import llm
from services.prompt import (
    get_system_prompt, construir_user_prompt, construir_mensaje_datos,
)
from db.repository import (
    get_historial_host, get_hosts_bloqueados, get_hosts_riesgo,
    get_estado_red, esta_en_whitelist, get_whitelist,
)
from integrations.ryu_rest import get_flujos, get_puertos

logger = logging.getLogger('AgenteSDN.monolitico')

SEP = '─' * 55

_VEREDICTO_FALLBACK = {
    'estado':                         'veredicto_final',
    'veredicto':                      'indeterminado',
    'severidad':                      'alta',
    'confianza':                      0,
    'nivel_autonomia':                2,
    'razonamiento':                   'Fallback conservador -- revisar logs.',
    'acciones_automaticas':           ['mantener_bloqueo'],
    'acciones_pendientes_aprobacion': [],
    'hosts_en_riesgo':                [],
    'mensaje_telegram':               'Incidente sin veredicto -- revisar manualmente.',
    'recomendaciones_forenses':       ['Revisar manualmente el incidente'],
    'actualizar_estado_red':          {'nivel_alerta_red': 'ALTO'},
}


def _fallback(motivo: str) -> dict:
    """
    Veredicto conservador cuando el LLM no responde.
    El campo 'error' se guarda en la DB para que el fallback no se confunda
    con un veredicto 'indeterminado' real del modelo.
    """
    return {**_VEREDICTO_FALLBACK, 'error': motivo}


# =============================================================================
# Logging del razonamiento
# =============================================================================

def _log_request(messages: list[dict], turno: int) -> None:
    """Imprime el prompt que se envia al LLM."""
    logger.info(f'\n{SEP}')
    logger.info(f'[LLM REQUEST] Turno {turno} -- modelo: {OPENAI_MODEL}')
    logger.info(SEP)
    for msg in messages:
        role = msg['role'].upper()
        content = msg['content']
        # Truncar system prompt para no saturar los logs
        if role == 'SYSTEM':
            logger.info(f'[{role}] (primeras 300 chars)\n{content[:300]}...')
        else:
            logger.info(f'[{role}]\n{content}')
    logger.info(SEP)


def _log_response(raw: str, parsed: dict, turno: int) -> None:
    """Imprime la respuesta completa del LLM con formato legible."""
    logger.info(f'\n{SEP}')
    logger.info(f'[LLM RESPONSE] Turno {turno}')
    logger.info(SEP)

    estado = parsed.get('estado', 'desconocido')

    if estado == 'necesito_datos':
        logger.info(f'  Estado:    SOLICITUD DE DATOS')
        logger.info(f'  Solicita:  {parsed.get("solicitud")}')
        logger.info(f'  Parametros:{parsed.get("parametros")}')
        logger.info(f'  Razon:     {parsed.get("razon")}')

    elif estado == 'veredicto_final':
        veredicto  = parsed.get('veredicto', '?')
        confianza  = parsed.get('confianza', 0)
        severidad  = parsed.get('severidad', '?')
        nivel      = parsed.get('nivel_autonomia', '?')
        razon      = parsed.get('razonamiento', '')
        acciones_a = parsed.get('acciones_automaticas', [])
        acciones_p = parsed.get('acciones_pendientes_aprobacion', [])
        hosts_r    = parsed.get('hosts_en_riesgo', [])
        forenses   = parsed.get('recomendaciones_forenses', [])
        telegram   = parsed.get('mensaje_telegram', '')

        # Icono segun veredicto
        icono = {
            'confirmado':    '🚨 CONFIRMADO',
            'falso_positivo':'✅ FALSO POSITIVO',
            'indeterminado': '⚠️  INDETERMINADO',
            'ya_contenido':  '🔒 YA CONTENIDO',
        }.get(veredicto, veredicto.upper())

        logger.info(f'  Veredicto:   {icono}')
        logger.info(f'  Severidad:   {severidad.upper()}')
        logger.info(f'  Confianza:   {confianza}%')
        logger.info(f'  Nivel HITL:  {nivel}')
        logger.info(f'')
        logger.info(f'  RAZONAMIENTO:')
        # Imprimir el razonamiento en lineas de maximo 70 chars
        for linea in _wrap(razon, 70):
            logger.info(f'    {linea}')
        logger.info(f'')
        if acciones_a:
            logger.info(f'  Acciones automaticas:')
            for a in acciones_a:
                logger.info(f'    -> {a}')
        if acciones_p:
            logger.info(f'  Acciones pendientes (HITL):')
            for a in acciones_p:
                logger.info(f'    -> {a} (requiere aprobacion)')
        if hosts_r:
            logger.info(f'  Hosts en riesgo: {hosts_r}')
        if forenses:
            logger.info(f'  Recomendaciones forenses:')
            for r in forenses:
                logger.info(f'    * {r}')
        if telegram:
            logger.info(f'  Mensaje Telegram:')
            logger.info(f'    {telegram}')

    else:
        logger.info(f'  Respuesta raw:\n{raw}')

    logger.info(SEP)


def _log_error(e: Exception, raw: str = '') -> None:
    """Imprime el error con contexto."""
    logger.error(f'\n{SEP}')
    logger.error(f'[LLM ERROR] {type(e).__name__}: {e}')
    if raw:
        logger.error(f'  Raw response: {raw[:500]}')
    logger.error(SEP)


def _wrap(texto: str, ancho: int) -> list:
    """Divide un texto en lineas de maximo ancho caracteres."""
    palabras = texto.split()
    lineas, linea = [], ''
    for p in palabras:
        if len(linea) + len(p) + 1 <= ancho:
            linea = (linea + ' ' + p).strip()
        else:
            if linea:
                lineas.append(linea)
            linea = p
    if linea:
        lineas.append(linea)
    return lineas or [texto]



# =============================================================================
# Llamada al LLM con el log del turno
# =============================================================================

def _llamar_openai(messages: list[dict], turno: int) -> dict:
    raw = llm.completar(messages)
    parsed = llm.extraer_json(raw)

    # Log de la respuesta completa
    _log_response(raw, parsed, turno)
    return parsed


# =============================================================================
# Resolucion de solicitudes de datos
# =============================================================================

def _resolver_solicitud(solicitud: str, parametros: dict) -> dict:
    if solicitud == 'historial_host':
        ip = parametros.get('ip', '')
        historial = get_historial_host(ip)
        datos = {
            'ip':                 ip,
            'incidentes_previos': len(historial),
            'primer_incidente':   len(historial) == 0,
            'en_whitelist':       esta_en_whitelist(ip),
            'historial':          historial,
        }
        logger.info(f'[LLM] Datos resueltos (historial_host): '
                    f'{len(historial)} incidentes previos para {ip}')
        return datos
    elif solicitud == 'flujos_switch':
        dpid = parametros.get('dpid', 1)
        flujos = get_flujos(dpid)
        n = len(flujos.get(str(dpid), []))
        logger.info(f'[LLM] Datos resueltos (flujos_switch): {n} flujos en DPID={dpid}')
        return {'dpid': dpid, 'flujos': flujos}
    elif solicitud == 'estado_puertos':
        dpid = parametros.get('dpid', 1)
        return {'dpid': dpid, 'puertos': get_puertos(dpid)}
    elif solicitud == 'hosts_bloqueados':
        hosts = get_hosts_bloqueados()
        logger.info(f'[LLM] Datos resueltos (hosts_bloqueados): {len(hosts)} hosts')
        return {'hosts': hosts}
    elif solicitud == 'hosts_riesgo':
        hosts = get_hosts_riesgo()
        logger.info(f'[LLM] Datos resueltos (hosts_riesgo): {len(hosts)} hosts')
        return {'hosts': hosts}
    return {'error': f'Solicitud desconocida: {solicitud}'}


# =============================================================================
# Loop bidireccional principal
# =============================================================================

def analizar_incidente(payload: dict) -> dict:
    """
    Loop ReAct con OpenRouter.
    Loguea cada turno completo -- request y response -- para trazabilidad.
    """
    src_ip = payload.get('host_origen', 'desconocido')

    logger.info(f'\n{"=" * 55}')
    logger.info(f'[LLM] INICIO ANALISIS -- host: {src_ip}')
    logger.info(f'[LLM] puntaje={payload.get("puntaje_total")} '
                f'metricas={payload.get("umbrales_superados")}')
    logger.info(f'{"=" * 55}')

    estado_red       = get_estado_red()
    hosts_bloqueados = get_hosts_bloqueados()
    hosts_riesgo     = get_hosts_riesgo()

    # La whitelist y el historial van en el primer mensaje: los modelos
    # pequenos casi nunca piden datos, y sin ellos un caso legitimo no
    # se puede distinguir de un ataque.
    user_prompt = construir_user_prompt(
        payload, estado_red, hosts_bloqueados, hosts_riesgo,
        whitelist=get_whitelist(src_ip),
        historial=get_historial_host(src_ip),
    )
    messages = [
        {'role': 'system', 'content': get_system_prompt()},
        {'role': 'user',   'content': user_prompt},
    ]

    for turno in range(1, MAX_TURNOS_LLM + 1):
        logger.info(f'[LLM] -- Turno {turno}/{MAX_TURNOS_LLM} --')
        _log_request(messages, turno)

        try:
            respuesta = _llamar_openai(messages, turno)

        except urllib.error.HTTPError as e:
            body = e.read().decode()
            _log_error(e, body)
            if e.code == 429:
                logger.warning('[LLM] Rate limit -- retornando fallback')
            elif e.code == 402:
                logger.warning('[LLM] Creditos insuficientes en OpenRouter')
            return _fallback(f'HTTP {e.code} en turno {turno}: {body[:300]}')

        except (urllib.error.URLError, ValueError, Exception) as e:
            _log_error(e)
            return _fallback(f'{type(e).__name__} en turno {turno}: {str(e)[:300]}')

        estado_respuesta = respuesta.get('estado')

        if estado_respuesta == 'necesito_datos':
            solicitud  = respuesta.get('solicitud', '')
            parametros = respuesta.get('parametros', {})
            datos      = _resolver_solicitud(solicitud, parametros)
            msg_datos  = construir_mensaje_datos(solicitud, datos)
            messages.append({'role': 'assistant', 'content': json.dumps(respuesta)})
            messages.append({'role': 'user',      'content': msg_datos})

        elif estado_respuesta == 'veredicto_final':
            logger.info(
                f'\n[LLM] FIN ANALISIS -- {src_ip}\n'
                f'  veredicto={respuesta.get("veredicto")} '
                f'confianza={respuesta.get("confianza")}% '
                f'turnos_usados={turno}/{MAX_TURNOS_LLM}'
            )
            return respuesta

        else:
            logger.warning('[LLM] Respuesta sin campo "estado" -- asumiendo veredicto final')
            respuesta['estado'] = 'veredicto_final'
            return respuesta

    logger.warning(f'[LLM] Limite de turnos alcanzado para {src_ip} -- fallback')
    return _fallback(f'Limite de {MAX_TURNOS_LLM} turnos alcanzado sin veredicto final')
