"""
api/routes_demo.py
Interfaz web /demo y ejecucion de los escenarios de prueba desde ella.
"""

import logging
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api.routes_acciones import verificar_api_key
from api.websocket import ws_manager
from services import escenarios

logger = logging.getLogger('AgenteSDN.routes.demo')

router = APIRouter(tags=['Demo'])

PAGINA = Path(__file__).resolve().parent.parent / 'frontend' / 'demo.html'


@router.get('/demo', include_in_schema=False)
def demo():
    """Interfaz web que muestra en vivo la interaccion Ryu <-> agente."""
    return FileResponse(PAGINA)


@router.get('/demo/escenarios', summary='Escenarios de prueba disponibles')
def listar_escenarios():
    return [{
        'id':            c['id'],
        'nombre':        c['nombre'],
        'clase':         c['clase'],
        'conjunto':      c['conjunto'],
        'escenario':     c['escenario'],
        'justificacion': c.get('justificacion', ''),
        'esperado':      c['esperado'],
        'contexto':      c.get('contexto', {}),
        'alerta':        c['alerta'],
    } for c in escenarios.cargar()]


@router.post('/demo/escenarios/{caso_id}/preparar',
             summary='Prepara la DB para un escenario y devuelve su alerta',
             dependencies=[Depends(verificar_api_key)])
async def preparar_escenario(caso_id: str):
    """
    Borra incidentes, bloqueos, hosts en riesgo y whitelist de la DB del
    agente, siembra el contexto del escenario y devuelve la alerta que hay
    que enviar a POST /alert.
    """
    caso = escenarios.buscar(caso_id)
    if caso is None:
        raise HTTPException(404, f'Escenario desconocido: {caso_id}')

    payload = escenarios.preparar(caso)
    logger.info(f'[Demo] Escenario {caso_id} preparado ({caso["nombre"]})')
    await ws_manager.broadcast({
        'tipo':     'escenario_preparado',
        'id':       caso_id,
        'nombre':   caso['nombre'],
        'host':     payload['host_origen'],
        'contexto': caso.get('contexto', {}),
        'ts':       datetime.utcnow().isoformat() + 'Z',
    })
    return payload
