"""
api/routes_dashboard.py
Endpoints de solo lectura para el dashboard frontend.
Todos los datos vienen de db/repository.py o de integrations/ryu_rest.py.
"""

import logging
from fastapi import APIRouter, Query

from db.repository import (
    get_estado_red,
    get_incidentes,
    get_hosts_bloqueados,
    get_hosts_riesgo,
    get_historial_host,
    get_umbrales,
)
from integrations.ryu_rest import get_flujos, get_topologia_switches, get_topologia_hosts
from integrations.telegram import get_acciones_pendientes
from api.websocket import ws_manager

logger = logging.getLogger('AgenteSDN.routes.dashboard')

router = APIRouter(tags=['Dashboard'])


@router.get('/estado', summary='Estado actual de la red')
def estado_red():
    """
    Resumen del estado actual:
    nivel de alerta, hosts bloqueados/en riesgo y acciones HITL pendientes.
    """
    return {
        'estado_red':        get_estado_red(),
        'hosts_bloqueados':  get_hosts_bloqueados(),
        'hosts_en_riesgo':   get_hosts_riesgo(),
        'hitl_pendientes':   len(get_acciones_pendientes()),
        'ws_clientes':       ws_manager.num_clientes,
    }


@router.get('/incidentes', summary='Historial de incidentes')
def listar_incidentes(limite: int = Query(default=50, ge=1, le=500)):
    return get_incidentes(limite)


@router.get('/hosts', summary='Estado de todos los hosts')
def estado_hosts():
    return {
        'bloqueados': get_hosts_bloqueados(),
        'en_riesgo':  get_hosts_riesgo(),
    }


@router.get('/hosts/{ip}/historial', summary='Historial de incidentes de un host')
def historial_host(ip: str, limite: int = Query(default=10, ge=1, le=100)):
    return {
        'ip':       ip,
        'historial': get_historial_host(ip, limite),
    }


@router.get('/flujos/{dpid}', summary='Flujos activos en un switch')
def flujos_switch(dpid: int):
    return get_flujos(dpid)


@router.get('/topologia', summary='Topologia de la red SDN')
def topologia():
    return {
        'switches': get_topologia_switches(),
        'hosts':    get_topologia_hosts(),
    }


@router.get('/umbrales', summary='Umbrales de deteccion actuales')
def leer_umbrales():
    return get_umbrales()