"""
api/routes_alertas.py
Endpoint que recibe las alertas CRITICAS desde el controlador Ryu.
Solo responsabilidad de este archivo: recibir, validar y despachar.
La logica de procesamiento vive en services/agente.py.
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel

from config import PLAZO_RESPUESTA_RYU_SEC
from services.agente import (
    procesar_alerta, respuesta_para_ryu, RESPUESTA_PROVISIONAL_RYU,
)
from api.websocket import ws_manager

logger = logging.getLogger('AgenteSDN.routes.alertas')

router = APIRouter(tags=['Alertas'])

# Referencias a los analisis que siguen corriendo despues de responder a Ryu,
# para que el recolector de basura no los cancele
_analisis_en_curso: set[asyncio.Task] = set()


def _al_terminar(tarea: asyncio.Task) -> None:
    _analisis_en_curso.discard(tarea)
    # Marca la excepcion como leida: procesar_alerta ya la registro en el log
    if not tarea.cancelled():
        tarea.exception()


# --- Modelos de entrada -------------------------------------------------------

class AlertaRyu(BaseModel):
    timestamp:            str
    alerta_nivel:         str
    host_origen:          str
    dpid_switch:          str
    contexto_topologico:  str
    puntaje_total:        int
    puntaje_maximo:       Optional[int]  = 135
    metricas:             dict
    pesos_metricas:       Optional[dict] = {}
    umbrales_superados:   list
    ioc_activados:        list
    accion_ryu_previa:    str
    solicitud_al_agente:  Optional[str]  = ''


# --- Endpoints ----------------------------------------------------------------

@router.post('/alert', summary='Recibe alerta CRITICA del controlador Ryu')
async def recibir_alerta(alerta: AlertaRyu):
    """
    Ryu llama a este endpoint cuando un host supera el puntaje critico y
    espera la respuesta como maximo AGENT_TIMEOUT segundos.
    Si el analisis termina antes de PLAZO_RESPUESTA_RYU_SEC se responde el
    veredicto final; si no, un veredicto provisional (mantener bloqueo) y
    el analisis sigue en segundo plano hasta registrarse en la DB.
    """
    payload = alerta.model_dump()
    logger.info(
        f'[/alert] Alerta recibida: {payload["host_origen"]} '
        f'puntaje={payload["puntaje_total"]}'
    )

    # Notificar al frontend que llego una alerta
    await ws_manager.broadcast({
        'tipo':    'alerta_recibida',
        'host':    payload['host_origen'],
        'puntaje': payload['puntaje_total'],
        'ts':      payload['timestamp'],
        'alerta':  payload,
    })

    tarea = asyncio.create_task(procesar_alerta(payload, ws_manager.emit_sync))
    _analisis_en_curso.add(tarea)
    tarea.add_done_callback(_al_terminar)

    try:
        respuesta = await asyncio.wait_for(asyncio.shield(tarea), PLAZO_RESPUESTA_RYU_SEC)
        para_ryu = respuesta_para_ryu(respuesta)
    except asyncio.TimeoutError:
        logger.info(f'[/alert] Plazo de {PLAZO_RESPUESTA_RYU_SEC}s agotado para '
                    f'{payload["host_origen"]} -- respuesta provisional')
        para_ryu = dict(RESPUESTA_PROVISIONAL_RYU)
    except Exception:
        # procesar_alerta ya registro el error en el log
        para_ryu = dict(RESPUESTA_PROVISIONAL_RYU)

    await ws_manager.broadcast({
        'tipo':      'respuesta_ryu',
        'host':      payload['host_origen'],
        'respuesta': para_ryu,
        'ts':        _ahora(),
    })
    return para_ryu


def _ahora() -> str:
    return datetime.utcnow().isoformat() + 'Z'
