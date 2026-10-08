# -*- coding: utf-8 -*-
"""
services/llm.py
Cliente HTTP de OpenRouter (formato OpenAI) y extraccion del JSON de la
respuesta. No conoce prompts: solo envia mensajes y devuelve
el objeto JSON que respondio el modelo.
"""

import json
import re
import logging
import urllib.request

from config import (
    OPENAI_API_KEY, OPENAI_MODEL, OPENAI_TEMP,
    OPENAI_MAX_TOKENS, OPENAI_URL, OPENAI_TIMEOUT,
    OPENROUTER_SITE_URL, OPENROUTER_APP_NAME,
)

logger = logging.getLogger('AgenteSDN.llm')


# =============================================================================
# Parseo tolerante de la respuesta
# =============================================================================

_IP_SUELTA = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')


def _citar_ips_sueltas(texto: str) -> str:
    """
    Pone comillas a las IPs escritas sin ellas fuera de los strings JSON,
    p. ej. "hosts_en_riesgo": [10.0.10.2] -> ["10.0.10.2"]. Los modelos
    pequenos lo hacen a menudo. Las IPs dentro de strings no se tocan.
    """
    salida, i, en_string = [], 0, False
    while i < len(texto):
        c = texto[i]
        if en_string:
            salida.append(c)
            if c == '\\' and i + 1 < len(texto):
                salida.append(texto[i + 1])
                i += 1
            elif c == '"':
                en_string = False
        elif c == '"':
            en_string = True
            salida.append(c)
        else:
            m = _IP_SUELTA.match(texto, i)
            if m:
                salida.append(f'"{m.group()}"')
                i = m.end()
                continue
            salida.append(c)
        i += 1
    return ''.join(salida)


def extraer_json(raw: str):
    """
    Parsea la respuesta del LLM, recortando texto extra y citando IPs sueltas.
    Lanza json.JSONDecodeError si no hay JSON valido.
    """
    candidatos = [raw]
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if match:
        candidatos.append(match.group())
    for texto in candidatos:
        for intento in (texto, _citar_ips_sueltas(texto)):
            try:
                return json.loads(intento)
            except json.JSONDecodeError:
                continue
    # Relanzar el error del recorte, que es el mas informativo
    return json.loads(_citar_ips_sueltas(candidatos[-1]))


# =============================================================================
# Llamada HTTP a OpenRouter
# =============================================================================

def completar(messages: list[dict]) -> str:
    """
    Envia la conversacion y devuelve el texto de la respuesta.
    Lanza urllib.error.HTTPError / URLError en fallos de red y ValueError
    si OpenRouter responde con un error.
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
            'HTTP-Referer':  OPENROUTER_SITE_URL,
            'X-Title':       OPENROUTER_APP_NAME,
        },
        method='POST',
    )

    with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT) as resp:
        data = json.loads(resp.read())

    if 'error' in data:
        raise ValueError(f'OpenRouter error: {data["error"].get("message", str(data["error"]))}')

    raw = (data['choices'][0]['message']['content'] or '').strip()
    logger.info(f'[LLM RAW COMPLETO]\n{raw}')
    return raw


def llamar_llm(system: str, user: str) -> dict:
    """
    Una llamada de un solo turno: system + user -> objeto JSON del modelo.
    Lanza json.JSONDecodeError si la respuesta no es JSON (o no es un objeto).
    """
    raw = completar([
        {'role': 'system', 'content': system},
        {'role': 'user',   'content': user},
    ])
    parsed = extraer_json(raw)
    if not isinstance(parsed, dict):
        raise json.JSONDecodeError('La respuesta no es un objeto JSON', raw, 0)
    return parsed
