"""
api/routes_acciones.py
Endpoints que el operador usa desde el dashboard para actuar sobre la red:
  - Bloquear / desbloquear hosts
  - Aislar subredes
  - Actualizar umbrales
  - Consultar el LLM manualmente
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import integrations.ryu_rest as ryu
from db.repository import (
    desbloquear_host_db,
    agregar_whitelist,
    set_umbral,
    get_historial_host,
)
from api.websocket import ws_manager

logger = logging.getLogger('AgenteSDN.routes.acciones')

router = APIRouter(tags=['Acciones'])


# --- Modelos ------------------------------------------------------------------

class AccionManual(BaseModel):
    accion: str                  # bloquear_host | desbloquear_host | bloquear_subred | whitelist
    ip:     Optional[str] = None
    subred: Optional[str] = None
    dpid:   Optional[int] = 1
    razon:  Optional[str] = ''


class UmbralesUpdate(BaseModel):
    M1:               Optional[int] = None
    M2:               Optional[int] = None
    M3_duration:      Optional[int] = None
    M3_bytes:         Optional[int] = None
    M4:               Optional[int] = None
    M5:               Optional[int] = None
    score_critical:   Optional[int] = None
    score_suspicious: Optional[int] = None


# --- Acciones manuales --------------------------------------------------------

@router.post('/accion', summary='Ejecutar accion manual en la red')
async def accion_manual(accion: AccionManual):
    """
    Permite al operador actuar directamente sobre la red desde el dashboard.
    Todas las acciones se registran y se emiten como eventos al frontend.
    """
    if accion.accion == 'bloquear_host':
        if not accion.ip:
            raise HTTPException(400, 'Se requiere el campo ip')
        resultado = ryu.bloquear_host(accion.ip, accion.dpid)
        await ws_manager.broadcast({
            'tipo':   'host_bloqueado',
            'ip':     accion.ip,
            'origen': 'manual',
        })
        return {'status': 'bloqueado', 'ip': accion.ip, 'resultado': resultado}

    elif accion.accion == 'desbloquear_host':
        if not accion.ip:
            raise HTTPException(400, 'Se requiere el campo ip')
        resultado = ryu.desbloquear_host(accion.ip, accion.dpid)
        desbloquear_host_db(accion.ip)
        await ws_manager.broadcast({
            'tipo':   'host_desbloqueado',
            'ip':     accion.ip,
            'origen': 'manual',
        })
        return {'status': 'desbloqueado', 'ip': accion.ip, 'resultado': resultado}

    elif accion.accion == 'bloquear_subred':
        if not accion.subred:
            raise HTTPException(400, 'Se requiere el campo subred (ej: 10.0.10.0/24)')
        resultado = ryu.bloquear_subred(accion.subred, accion.dpid)
        await ws_manager.broadcast({
            'tipo':   'subred_bloqueada',
            'subred': accion.subred,
            'origen': 'manual',
        })
        return {'status': 'bloqueada', 'subred': accion.subred, 'resultado': resultado}

    elif accion.accion == 'whitelist':
        if not accion.ip:
            raise HTTPException(400, 'Se requiere el campo ip')
        agregar_whitelist(accion.ip, accion.razon or 'Agregado manualmente')
        ryu.desbloquear_host(accion.ip, accion.dpid)
        desbloquear_host_db(accion.ip)
        await ws_manager.broadcast({
            'tipo':   'host_en_whitelist',
            'ip':     accion.ip,
            'origen': 'manual',
        })
        return {'status': 'whitelist', 'ip': accion.ip}

    elif accion.accion == 'historial':
        if not accion.ip:
            raise HTTPException(400, 'Se requiere el campo ip')
        return {'ip': accion.ip, 'historial': get_historial_host(accion.ip)}

    raise HTTPException(400, f'Accion desconocida: {accion.accion}')


# --- Umbrales -----------------------------------------------------------------

@router.post('/umbrales', summary='Actualizar umbrales de deteccion')
async def actualizar_umbrales(umbrales: UmbralesUpdate):
    """
    Actualiza los umbrales en la DB y notifica al frontend.
    Para que los nuevos umbrales sean efectivos en Ryu,
    es necesario reiniciar el controlador o usar la REST API de Ryu
    si se implementa un endpoint de configuracion en ryu_controller.py.
    """
    cambios = {k: v for k, v in umbrales.model_dump().items() if v is not None}
    if not cambios:
        raise HTTPException(400, 'No se proporcionaron umbrales para actualizar')

    for nombre, valor in cambios.items():
        set_umbral(nombre, valor)

    await ws_manager.broadcast({
        'tipo':     'umbrales_actualizados',
        'umbrales': cambios,
    })
    logger.info(f'[Umbrales] Actualizados desde dashboard: {cambios}')
    return {'status': 'actualizado', 'umbrales': cambios}