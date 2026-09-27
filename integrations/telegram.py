"""
integrations/telegram.py
Toda la comunicacion con Telegram vive aqui.
Expone funciones simples para el resto del sistema:
  - enviar_texto()
  - enviar_hitl()
  - iniciar_polling()

El estado de las acciones pendientes (tokens HITL) tambien vive aqui
porque es responsabilidad directa de esta integracion.
"""

import json
import time
import uuid
import logging
import threading
import urllib.request
import urllib.error
from typing import Callable

from config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    TELEGRAM_ENABLED, TELEGRAM_POLL_SEC,
    HITL_TIMEOUT_SEGUNDOS,
)

logger = logging.getLogger('AgenteSDN.telegram')

BASE_URL = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}'

# Acciones pendientes de confirmacion: {token: {accion, parametros, expira, host}}
_acciones_pendientes: dict = {}
_ultimo_update_id   = 0

# Callback que se llama cuando el operador aprueba o rechaza
# Se inyecta desde services/agente.py al iniciar el polling
_on_aprobado: Callable | None = None
_on_rechazado: Callable | None = None


# ===============================================================================
# HTTP helper - privado
# ===============================================================================

def _post(metodo: str, body: dict) -> dict:
    if not TELEGRAM_ENABLED:
        logger.debug(f'[Telegram] DESHABILITADO - {metodo}: {str(body)[:80]}')
        return {}
    data = json.dumps(body).encode('utf-8')
    req  = urllib.request.Request(
        f'{BASE_URL}/{metodo}',
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        logger.error(f'[Telegram] Error en {metodo}: {e}')
        return {}
    except Exception as e:
        logger.error(f'[Telegram] Error inesperado en {metodo}: {e}')
        return {}


def _get_updates(offset: int) -> list:
    url = f'{BASE_URL}/getUpdates?offset={offset}&timeout={TELEGRAM_POLL_SEC}'
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=TELEGRAM_POLL_SEC + 5) as resp:
            data = json.loads(resp.read())
            return data.get('result', [])
    except Exception:
        return []


# ===============================================================================
# API publica
# ===============================================================================

def enviar_texto(texto: str) -> None:
    """Envia un mensaje de texto simple al chat configurado."""
    _post('sendMessage', {
        'chat_id':    TELEGRAM_CHAT_ID,
        'text':       texto,
        'parse_mode': 'HTML',
    })
    logger.info(f'[Telegram] Mensaje enviado: {texto[:80]}')


def enviar_hitl(texto: str, accion: str, parametros: dict, host: str) -> str:
    """
    Envia un mensaje con botones inline [OK]/[X] al operador.
    Retorna el token generado para esta accion pendiente.
    """
    token = uuid.uuid4().hex[:8]
    _acciones_pendientes[token] = {
        'accion':     accion,
        'parametros': parametros,
        'host':       host,
        'expira':     time.time() + HITL_TIMEOUT_SEGUNDOS,
    }
    _post('sendMessage', {
        'chat_id':    TELEGRAM_CHAT_ID,
        'text':       texto,
        'parse_mode': 'HTML',
        'reply_markup': {
            'inline_keyboard': [[
                {'text': '[OK] APROBAR', 'callback_data': f'aprobar_{token}'},
                {'text': '[X] RECHAZAR', 'callback_data': f'rechazar_{token}'},
            ]]
        },
    })
    logger.info(f'[Telegram] HITL enviado - token: {token}, accion: {accion}')
    return token


def get_acciones_pendientes() -> dict:
    """Retorna una copia del estado de acciones pendientes."""
    return dict(_acciones_pendientes)


def limpiar_pendientes_expirados() -> int:
    """Elimina acciones cuyo timeout ya paso. Retorna la cantidad eliminada."""
    ahora   = time.time()
    expirados = [t for t, p in _acciones_pendientes.items() if ahora > p['expira']]
    for t in expirados:
        del _acciones_pendientes[t]
        logger.info(f'[Telegram] Token expirado eliminado: {t}')
    return len(expirados)


# ===============================================================================
# Polling de respuestas del operador
# ===============================================================================

def _procesar_callback(callback_data: str, callback_id: str) -> None:
    """Procesa un callback_query de Telegram (boton pulsado por el operador)."""
    global _ultimo_update_id

    if callback_data.startswith('aprobar_'):
        token    = callback_data[8:]
        pendiente = _acciones_pendientes.pop(token, None)
        if not pendiente:
            enviar_texto('[AVISO] Token invalido o ya procesado.')
            return
        if time.time() > pendiente['expira']:
            enviar_texto('[TIEMPO] El tiempo de aprobacion expiro - accion cancelada.')
            return
        logger.info(f'[Telegram] Operador APROBO: {pendiente["accion"]}')
        if _on_aprobado:
            _on_aprobado(pendiente)

    elif callback_data.startswith('rechazar_'):
        token    = callback_data[9:]
        pendiente = _acciones_pendientes.pop(token, None)
        if pendiente:
            logger.info(f'[Telegram] Operador RECHAZO: {pendiente["accion"]}')
            enviar_texto(
                f'[X] Accion <b>{pendiente["accion"]}</b> rechazada.\n'
                f'El estado de la red se mantiene sin cambios.'
            )
            if _on_rechazado:
                _on_rechazado(pendiente)

    # Responder al callback para quitar el indicador del boton en Telegram
    _post('answerCallbackQuery', {
        'callback_query_id': callback_id,
        'text':              'Procesado',
    })


def _polling_loop() -> None:
    """Hilo de polling que escucha respuestas del operador cada N segundos."""
    global _ultimo_update_id
    logger.info('[Telegram] Polling iniciado')
    while True:
        try:
            updates = _get_updates(_ultimo_update_id + 1)
            for update in updates:
                _ultimo_update_id = update['update_id']
                callback = update.get('callback_query')
                if callback:
                    _procesar_callback(
                        callback.get('data', ''),
                        callback.get('id', ''),
                    )
            limpiar_pendientes_expirados()
        except Exception as e:
            logger.debug(f'[Telegram] Polling error: {e}')
        time.sleep(TELEGRAM_POLL_SEC)


def iniciar_polling(on_aprobado: Callable, on_rechazado: Callable) -> None:
    """
    Inicia el hilo de polling en background.
    Recibe callbacks que se ejecutan cuando el operador responde.
    """
    global _on_aprobado, _on_rechazado
    _on_aprobado  = on_aprobado
    _on_rechazado = on_rechazado
    if not TELEGRAM_ENABLED:
        logger.info('[Telegram] DESHABILITADO - polling no iniciado')
        return
    t = threading.Thread(target=_polling_loop, daemon=True)
    t.start()