"""
services/agente.py
Orquestador central. Coordina el flujo completo de un incidente:
  1. Recibe el payload de Ryu (que ya bloqueo el equipo)
  2. Lo analiza con el LLM (services/analisis.py)
  3. Registra el resultado en la DB (db/repository.py)
  4. Notifica por Telegram (integrations/telegram.py), solo informativo
  5. Emite eventos al WebSocket (api/websocket.py)

El agente no ejecuta acciones en la red: el bloqueo de Ryu se mantiene y
los desbloqueos los hace el operador a mano (POST /accion).

Este módulo es el único que conoce a todas las demás capas.
Las capas individuales no se conocen entre sí.
"""

import logging
from datetime import datetime
from typing import Callable

from config import TELEGRAM_ENABLED
from services.analisis import analizar_incidente
from db.repository import registrar_incidente
import integrations.telegram as telegram

logger = logging.getLogger('AgenteSDN.agente')

# Callback para emitir eventos al WebSocket
# Se inyecta desde api/routes_alertas.py al arrancar
_emit_ws: Callable | None = None

# Contrato de respuesta de Ryu-IA (_ejecutar_respuesta_agente)
VEREDICTOS_RYU  = {'confirmado', 'falso_positivo', 'indeterminado'}
SEVERIDADES_RYU = {'critica', 'alta', 'media'}

# Respuesta para Ryu cuando el LLM no termina dentro del plazo
RESPUESTA_PROVISIONAL_RYU = {
    'veredicto':        'indeterminado',
    'severidad':        'alta',
    'acciones_ryu':     ['mantener_bloqueo'],
    'mensaje_operador': 'Analisis del agente en curso: se mantiene el bloqueo '
                        'hasta el veredicto final.',
    'alertas':          [],
    'provisional':      True,
}


def set_ws_emitter(fn: Callable) -> None:
    """Registra la función que emite eventos al WebSocket del frontend."""
    global _emit_ws
    _emit_ws = fn


def _emit(evento: dict) -> None:
    """Emite un evento al WebSocket si hay un emitter registrado."""
    if _emit_ws:
        _emit_ws(evento)


# ═══════════════════════════════════════════════════════════════════════════════
# Respuesta a Ryu-IA
# ═══════════════════════════════════════════════════════════════════════════════

def respuesta_para_ryu(respuesta: dict) -> dict:
    """
    Traduce el veredicto al JSON que espera Ryu-IA.
    acciones_ryu es siempre mantener_bloqueo: el agente nunca desbloquea
    por su cuenta, aunque el veredicto sea falso_positivo.
    """
    veredicto = respuesta.get('veredicto', 'indeterminado')
    if veredicto not in VEREDICTOS_RYU:
        veredicto = 'indeterminado'

    severidad = respuesta.get('severidad')
    if severidad not in SEVERIDADES_RYU:
        severidad = 'alta'

    mensaje = respuesta.get('mensaje_telegram', '')
    return {
        'veredicto':        veredicto,
        'severidad':        severidad,
        'acciones_ryu':     ['mantener_bloqueo'],
        'mensaje_operador': mensaje,
        'alertas':          ['telegram'] if TELEGRAM_ENABLED and mensaje else [],
        'provisional':      False,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Función principal — punto de entrada del servicio
# ═══════════════════════════════════════════════════════════════════════════════

async def procesar_alerta(payload: dict, emit_fn: Callable | None = None) -> dict:
    """
    Procesa un incidente de punta a punta:
      1. Analiza con LLM
      2. Registra en DB
      3. Notifica por Telegram
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
        # Analizar con LLM (operación bloqueante — se ejecuta en un executor)
        loop = asyncio.get_event_loop()
        respuesta = await loop.run_in_executor(None, analizar_incidente, payload)

        # Registrar en DB
        registrar_incidente(payload, respuesta)

        # Solo notificar: el bloqueo de Ryu se mantiene
        telegram.enviar_texto(respuesta['mensaje_telegram'])

        _emit({
            'tipo':      'incidente_procesado',
            'host':      src_ip,
            'veredicto': respuesta.get('veredicto'),
            'ts':        datetime.utcnow().isoformat() + 'Z',
        })

        logger.info(
            f'[Agente] ✓ Incidente procesado: {src_ip} → '
            f'{respuesta.get("veredicto")}'
        )
        return respuesta

    except Exception as e:
        logger.error(f'[Agente] Error procesando alerta de {src_ip}: {e}', exc_info=True)
        _emit({'tipo': 'error', 'host': src_ip, 'error': str(e)})
        raise


def iniciar_servicios() -> None:
    """
    Inicializa todos los servicios del agente.
    Llamar una sola vez al arrancar la aplicación.
    """
    from db.database import init_db
    init_db()
    logger.info('[Agente] Todos los servicios iniciados correctamente')