"""
api/routes_alertas.py
Endpoint que recibe las alertas CRITICAS desde el controlador Ryu.
Solo responsabilidad de este archivo: recibir, validar y despachar.
La logica de procesamiento vive en services/agente.py.
"""

import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from services.agente import procesar_alerta
from api.websocket import ws_manager

logger = logging.getLogger('AgenteSDN.routes.alertas')

router = APIRouter(tags=['Alertas'])


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
async def recibir_alerta(alerta: AlertaRyu, background_tasks: BackgroundTasks):
    """
    Ryu llama a este endpoint cuando un host supera el puntaje critico.
    Responde inmediatamente con 200 para no bloquear el event loop de Ryu,
    y procesa el incidente en background.
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
    })

    # Procesar en background con acceso al ws_manager
    background_tasks.add_task(
        procesar_alerta,
        payload,
        ws_manager.emit_sync,
    )

    return {
        'status': 'recibido',
        'host':   payload['host_origen'],
        'msg':    'Procesando en background',
    }