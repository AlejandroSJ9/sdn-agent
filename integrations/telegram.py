"""
integrations/telegram.py
Notificaciones al operador por Telegram. Solo informan: el agente no
espera respuestas ni botones del operador.
"""

import json
import logging
import urllib.request
import urllib.error

from config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ENABLED

logger = logging.getLogger('AgenteSDN.telegram')

BASE_URL = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}'


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


def enviar_texto(texto: str) -> None:
    """Envia un mensaje de texto (HTML simple) al chat configurado."""
    _post('sendMessage', {
        'chat_id':    TELEGRAM_CHAT_ID,
        'text':       texto,
        'parse_mode': 'HTML',
    })
    logger.info(f'[Telegram] Mensaje enviado: {texto[:80]}')
