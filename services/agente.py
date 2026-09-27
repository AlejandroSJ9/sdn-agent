"""
services/agente.py
Orquestador central. Coordina el flujo completo de un incidente:
  1. Recibe el payload de Ryu
  2. Lo analiza con el LLM (services/llm.py)
  3. Registra el resultado en la DB (db/repository.py)
  4. Ejecuta acciones en Ryu (integrations/ryu_rest.py)
  5. Notifica por Telegram (integrations/telegram.py)
  6. Emite eventos al WebSocket (api/websocket.py)

Este modulo es el unico que conoce a todas las demas capas.
Las capas individuales no se conocen entre si.
"""

import logging
from datetime import datetime
from typing import Callable

from services.llm import analizar_incidente
from db.repository import (
    registrar_incidente,
    desbloquear_host_db,
)
import integrations.ryu_rest as ryu
import integrations.telegram as telegram

logger = logging.getLogger('AgenteSDN.agente')

# Callback para emitir eventos al WebSocket
# Se inyecta desde api/routes_alertas.py al arrancar
_emit_ws: Callable | None = None

PUERTOS_CRITICOS = [445, 135, 3389, 5985, 139]


def set_ws_emitter(fn: Callable) -> None:
    """Registra la funcion que emite eventos al WebSocket del frontend."""
    global _emit_ws
    _emit_ws = fn


def _emit(evento: dict) -> None:
    """Emite un evento al WebSocket si hay un emitter registrado."""
    if _emit_ws:
        _emit_ws(evento)


def _dpid_from_payload(payload: dict) -> int:
    """Extrae el DPID numerico del payload de Ryu."""
    dpid_str = payload.get('dpid_switch', '0x0000000000000001')
    try:
        return int(dpid_str, 16) if dpid_str.startswith('0x') else int(dpid_str)
    except (ValueError, TypeError):
        return 1


# ===============================================================================
# Callbacks de HITL - se pasan a telegram.iniciar_polling()
# ===============================================================================

def _on_aprobado(pendiente: dict) -> None:
    """
    Se ejecuta cuando el operador aprueba una accion via Telegram.
    """
    accion = pendiente.get('accion', '')
    params = pendiente.get('parametros', {})
    dpid   = params.get('dpid', 1)
    logger.info(f'[HITL] Operador APROBO: {accion} - {params}')

    if accion == 'bloquear_hosts':
        hosts = params.get('hosts', [])
        for h in hosts:
            ryu.bloquear_host(h, dpid)
        telegram.enviar_texto(
            f'[OK] <b>Accion ejecutada</b>\n'
            f'{len(hosts)} hosts bloqueados:\n' +
            '\n'.join(f'  - <code>{h}</code>' for h in hosts)
        )
        _emit({'tipo': 'hosts_bloqueados', 'hosts': hosts, 'origen': 'hitl'})

    elif accion == 'desbloquear_host':
        ip = params.get('ip', '')
        ryu.desbloquear_host(ip, dpid)
        desbloquear_host_db(ip)
        telegram.enviar_texto(f'[OK] Host <code>{ip}</code> desbloqueado.')
        _emit({'tipo': 'host_desbloqueado', 'ip': ip, 'origen': 'hitl'})

    elif accion == 'bloquear_subred':
        subred = params.get('subred', '')
        ryu.bloquear_subred(subred, dpid)
        telegram.enviar_texto(f'[OK] Subred <code>{subred}</code> bloqueada.')
        _emit({'tipo': 'subred_bloqueada', 'subred': subred, 'origen': 'hitl'})

    else:
        logger.warning(f'[HITL] Accion desconocida aprobada: {accion}')
        telegram.enviar_texto(f'[AVISO] Accion desconocida: {accion}')


def _on_rechazado(pendiente: dict) -> None:
    """Se ejecuta cuando el operador rechaza una accion via Telegram."""
    accion = pendiente.get('accion', '')
    logger.info(f'[HITL] Operador RECHAZO: {accion}')
    _emit({'tipo': 'hitl_rechazado', 'accion': accion})


# ===============================================================================
# Ejecucion de respuesta del LLM
# ===============================================================================

def _ejecutar_nivel_1(src_ip: str, dpid: int, respuesta: dict) -> None:
    """Nivel 1: acciones automaticas sin confirmacion."""
    for accion in respuesta.get('acciones_automaticas', []):
        if accion == 'mantener_bloqueo':
            logger.info(f'[Agente] Nivel 1 - manteniendo DROP de {src_ip}')

        elif accion == 'desbloquear_host':
            confianza = respuesta.get('confianza', 0)
            if confianza >= 85:
                ryu.desbloquear_host(src_ip, dpid)
                desbloquear_host_db(src_ip)
                logger.info(f'[Agente] Nivel 1 - host desbloqueado: {src_ip}')
            else:
                logger.warning(
                    f'[Agente] Desbloqueo rechazado - confianza insuficiente: '
                    f'{confianza}% < 85%'
                )

    # Siempre notificar al SOC con el mensaje informativo
    msg = respuesta.get('mensaje_telegram', '')
    if msg:
        telegram.enviar_texto(msg)


def _ejecutar_nivel_2(src_ip: str, dpid: int, respuesta: dict) -> None:
    """Nivel 2: enviar botones a Telegram y esperar confirmacion del operador."""
    pendientes = respuesta.get('acciones_pendientes_aprobacion', [])
    hosts_riesgo = respuesta.get('hosts_en_riesgo', [])
    msg  = respuesta.get('mensaje_telegram', '')

    # Determinar la accion principal y sus parametros
    accion_principal = pendientes[0] if pendientes else 'mantener_bloqueo'
    parametros: dict = {'dpid': dpid}

    if accion_principal in ('bloquear_hosts_adicionales', 'bloquear_hosts'):
        parametros['hosts']  = hosts_riesgo
        parametros['accion'] = 'bloquear_hosts'
    elif accion_principal == 'desbloquear_host':
        parametros['ip']     = src_ip
        parametros['accion'] = 'desbloquear_host'
    elif accion_principal == 'bloquear_subred':
        subred = src_ip.rsplit('.', 1)[0] + '.0/24'
        parametros['subred'] = subred
        parametros['accion'] = 'bloquear_subred'
    else:
        parametros['accion'] = accion_principal

    telegram.enviar_hitl(
        texto=msg,
        accion=parametros.get('accion', accion_principal),
        parametros=parametros,
        host=src_ip,
    )


def _ejecutar_nivel_3(src_ip: str, respuesta: dict) -> None:
    """Nivel 3: solo notificar - NO ejecutar nada en la red."""
    msg = respuesta.get('mensaje_telegram', '')
    urgente = (
        f'[URGENTE] <b>ALERTA URGENTE - NIVEL 3</b>\n\n'
        f'{msg}\n\n'
        f'[BLOQUEADO] <b>El agente NO ha ejecutado acciones automaticas.</b>\n'
        f'Se requiere aprobacion manual del operador.'
    )
    telegram.enviar_texto(urgente)
    logger.critical(
        f'[Agente] Nivel 3 - alerta urgente enviada para {src_ip}. '
        f'Sin acciones automaticas.'
    )


def _enviar_recomendaciones_forenses(src_ip: str, respuesta: dict) -> None:
    """Envia las recomendaciones forenses como mensaje separado."""
    forenses = respuesta.get('recomendaciones_forenses', [])
    if forenses:
        texto = (
            f'[INFO] <b>Recomendaciones forenses para <code>{src_ip}</code>:</b>\n' +
            '\n'.join(f'  - {r}' for r in forenses)
        )
        telegram.enviar_texto(texto)


def _ejecutar_respuesta(payload: dict, respuesta: dict) -> None:
    """
    Despacha la ejecucion al nivel de autonomia correspondiente.
    """
    nivel    = respuesta.get('nivel_autonomia', 1)
    src_ip   = payload['host_origen']
    dpid     = _dpid_from_payload(payload)

    logger.info(
        f'[Agente] Ejecutando respuesta - host={src_ip} '
        f'nivel={nivel} veredicto={respuesta.get("veredicto")}'
    )

    if nivel == 1:
        _ejecutar_nivel_1(src_ip, dpid, respuesta)
    elif nivel == 2:
        _ejecutar_nivel_2(src_ip, dpid, respuesta)
    elif nivel == 3:
        _ejecutar_nivel_3(src_ip, respuesta)
    else:
        logger.error(f'[Agente] Nivel de autonomia desconocido: {nivel}')
        telegram.enviar_texto(
            f'[AVISO] Nivel de autonomia desconocido ({nivel}) - revisar manualmente.'
        )

    _enviar_recomendaciones_forenses(src_ip, respuesta)


# ===============================================================================
# Funcion principal - punto de entrada del servicio
# ===============================================================================

async def procesar_alerta(payload: dict, emit_fn: Callable | None = None) -> dict:
    """
    Procesa un incidente de punta a punta:
      1. Analiza con LLM
      2. Registra en DB
      3. Ejecuta acciones
      4. Emite eventos al WebSocket

    Retorna el veredicto para que el caller pueda loguear o responder.
    """
    import asyncio
    global _emit_ws
    if emit_fn:
        _emit_ws = emit_fn

    src_ip = payload.get('host_origen', 'desconocido')
    logger.info(f'[Agente] Procesando alerta: {src_ip} '
                f'puntaje={payload.get("puntaje_total")}')

    _emit({
        'tipo':    'procesando',
        'host':    src_ip,
        'ts':      datetime.utcnow().isoformat() + 'Z',
    })

    try:
        # Analizar con LLM (operacion bloqueante - se ejecuta en un executor)
        loop = asyncio.get_event_loop()
        respuesta = await loop.run_in_executor(None, analizar_incidente, payload)

        # Registrar en DB
        registrar_incidente(payload, respuesta)

        # Ejecutar acciones en la red y notificaciones
        _ejecutar_respuesta(payload, respuesta)

        _emit({
            'tipo':      'incidente_procesado',
            'host':      src_ip,
            'veredicto': respuesta.get('veredicto'),
            'confianza': respuesta.get('confianza'),
            'nivel':     respuesta.get('nivel_autonomia'),
            'ts':        datetime.utcnow().isoformat() + 'Z',
        })

        logger.info(
            f'[Agente] Incidente procesado: {src_ip} -> '
            f'{respuesta.get("veredicto")} ({respuesta.get("confianza")}%)'
        )
        return respuesta

    except Exception as e:
        logger.error(f'[Agente] Error procesando alerta de {src_ip}: {e}', exc_info=True)
        _emit({'tipo': 'error', 'host': src_ip, 'error': str(e)})
        raise


def iniciar_servicios() -> None:
    """
    Inicializa todos los servicios del agente.
    Llamar una sola vez al arrancar la aplicacion.
    """
    from db.database import init_db
    init_db()
    telegram.iniciar_polling(
        on_aprobado=_on_aprobado,
        on_rechazado=_on_rechazado,
    )
    logger.info('[Agente] Todos los servicios iniciados correctamente')