"""
integrations/ryu_rest.py
Cliente para la REST API del controlador Ryu.
Toda comunicacion con Ryu pasa por aqui - el resto del sistema
no sabe como se comunica con Ryu, solo llama funciones de este modulo.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Any

from config import RYU_REST_URL, RYU_TIMEOUT

logger = logging.getLogger('AgenteSDN.ryu')


# ===============================================================================
# HTTP helpers - privados a este modulo
# ===============================================================================

def _get(endpoint: str) -> Any:
    url = f'{RYU_REST_URL}{endpoint}'
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=RYU_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        logger.error(f'[Ryu] GET {endpoint} - error de conexion: {e}')
        return {'error': str(e), 'endpoint': endpoint}
    except Exception as e:
        logger.error(f'[Ryu] GET {endpoint} - error inesperado: {e}')
        return {'error': str(e)}


def _post(endpoint: str, body: dict) -> Any:
    url  = f'{RYU_REST_URL}{endpoint}'
    data = json.dumps(body).encode('utf-8')
    req  = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=RYU_TIMEOUT) as resp:
            return json.loads(resp.read() or b'{}')
    except urllib.error.URLError as e:
        logger.error(f'[Ryu] POST {endpoint} - error de conexion: {e}')
        return {'error': str(e), 'endpoint': endpoint}
    except Exception as e:
        logger.error(f'[Ryu] POST {endpoint} - error inesperado: {e}')
        return {'error': str(e)}


# ===============================================================================
# API publica del modulo
# ===============================================================================

def get_flujos(dpid: int) -> dict:
    """Retorna los flujos activos de un switch."""
    return _get(f'/stats/flow/{dpid}')


def get_puertos(dpid: int) -> dict:
    """Retorna estadisticas de puertos de un switch."""
    return _get(f'/stats/port/{dpid}')


def get_topologia_switches() -> list:
    """Retorna la lista de switches conectados al controlador."""
    return _get('/v1.0/topology/switches')


def get_topologia_hosts() -> list:
    """Retorna los hosts conocidos por el controlador."""
    return _get('/v1.0/topology/hosts')


def bloquear_host(ip: str, dpid: int) -> dict:
    """
    Instala una regla OFPFlowMod DROP para el host indicado.
    Prioridad 100 - permanente (sin timeout).
    """
    resultado = _post('/stats/flowentry/add', {
        'dpid':     dpid,
        'priority': 100,
        'match':    {'dl_type': 2048, 'nw_src': ip},
        'actions':  [],
    })
    logger.info(f'[Ryu] DROP instalado: {ip} en DPID={dpid}')
    return resultado


def desbloquear_host(ip: str, dpid: int) -> dict:
    """
    Elimina la regla DROP del switch para el host indicado.
    """
    resultado = _post('/stats/flowentry/delete', {
        'dpid':     dpid,
        'priority': 100,
        'match':    {'dl_type': 2048, 'nw_src': ip},
    })
    logger.info(f'[Ryu] DROP eliminado: {ip} en DPID={dpid}')
    return resultado


def bloquear_subred(subred: str, dpid: int) -> dict:
    """
    Instala regla DROP para toda una subred (ej: 10.0.10.0/24).
    Prioridad 150 - gana sobre reglas individuales de host.
    """
    resultado = _post('/stats/flowentry/add', {
        'dpid':     dpid,
        'priority': 150,
        'match':    {'dl_type': 2048, 'nw_src': subred},
        'actions':  [],
    })
    logger.info(f'[Ryu] DROP de subred: {subred} en DPID={dpid}')
    return resultado


def aplicar_rate_limit(ip: str, dpid: int, puertos: list[int],
                        idle_timeout: int = 60) -> list[dict]:
    """
    Instala reglas de rate-limit (trafico al controller) para el host
    en los puertos criticos indicados. Las reglas expiran en idle_timeout segundos.
    """
    resultados = []
    for puerto in puertos:
        r = _post('/stats/flowentry/add', {
            'dpid':         dpid,
            'priority':     20,
            'idle_timeout': idle_timeout,
            'hard_timeout': idle_timeout * 2,
            'match':        {
                'dl_type': 2048,
                'nw_src':  ip,
                'ip_proto': 6,
                'tp_dst':   puerto,
            },
            'actions': [{'type': 'OUTPUT', 'port': 'CONTROLLER'}],
        })
        resultados.append(r)
    logger.info(f'[Ryu] Rate-limit aplicado: {ip} en puertos {puertos}')
    return resultados