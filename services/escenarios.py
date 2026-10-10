# -*- coding: utf-8 -*-
"""
services/escenarios.py
Escenarios de prueba (pruebas/escenarios.json) para ejecutarlos desde la
interfaz /demo. Cada escenario se prepara igual que en
pruebas/test_escenarios.py: se limpia la DB, se siembra su contexto
(whitelist, incidentes previos, hosts en riesgo, nivel de alerta) y se
construye la alerta como la enviaria Ryu-IA.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

from config import METRIC_WEIGHTS, SUBNET_ADM, SUBNET_OPS
from db.repository import (
    agregar_whitelist, borrar_datos_de_red, sembrar_host_riesgo,
    sembrar_incidente, set_estado_red,
)

ARCHIVO = Path(__file__).resolve().parent.parent / 'pruebas' / 'escenarios.json'

# Umbrales de Ryu-IA (ryu_controller.py)
UMBRAL_M1, UMBRAL_M2, UMBRAL_M4, UMBRAL_M5 = 20, 15, 200, 5
METRICAS_MINIMAS = 3


def cargar() -> list[dict]:
    return json.loads(ARCHIVO.read_text(encoding='utf-8'))['casos']


def buscar(caso_id: str) -> dict | None:
    return next((c for c in cargar() if c['id'] == caso_id), None)


# =============================================================================
# Alerta como la construye Ryu-IA (_send_json_alert)
# =============================================================================

def metricas_disparadas(a: dict) -> list[str]:
    disparadas = []
    if a['M1'] > UMBRAL_M1:        disparadas.append('M1')
    if a['M2'] > UMBRAL_M2:        disparadas.append('M2')
    if a['M3']:                    disparadas.append('M3')
    if a['M4'] > UMBRAL_M4:        disparadas.append('M4')
    if a['M5_count'] >= UMBRAL_M5: disparadas.append('M5')
    return sorted(disparadas)


def iocs(disparadas: list[str]) -> list[str]:
    """Copia de SDNRansomwareDetector._map_ioc."""
    t, out = set(disparadas), []
    if {'M1', 'M2'} <= t:          out.append('IOC-01')
    if 'M3' in t:                  out.append('IOC-02')
    if 'M4' in t:                  out.append('IOC-03')
    if 'M5' in t:                  out.append('IOC-04')
    if {'M5', 'M1'} <= t:          out.append('IOC-07')
    if len(t) >= METRICAS_MINIMAS: out.append('IOC-05')
    return sorted(set(out))


def contexto_topologico(ip: str) -> str:
    if ip.startswith(SUBNET_OPS):
        return 'VLAN OPS (ID=10), subred 10.0.10.0/24'
    if ip.startswith(SUBNET_ADM):
        return 'VLAN ADM (ID=20), subred 10.0.20.0/24'
    return 'subred desconocida'


def dpid(ip: str) -> str:
    return '0x0000000000000002' if ip.startswith(SUBNET_ADM) else '0x0000000000000001'


def puntaje(disparadas: list[str]) -> int:
    return sum(METRIC_WEIGHTS[m] for m in disparadas)


def construir_payload(a: dict, ts: str) -> dict:
    disparadas = metricas_disparadas(a)
    ip = a['host']
    return {
        'timestamp':           ts,
        'alerta_nivel':        'CRITICO',
        'host_origen':         ip,
        'dpid_switch':         dpid(ip),
        'contexto_topologico': contexto_topologico(ip),
        'puntaje_total':       puntaje(disparadas),
        'puntaje_maximo':      sum(METRIC_WEIGHTS.values()),
        'metricas': {
            'M1_nuevos_flujos_por_30s':   a['M1'],
            'M2_destinos_unicos_por_30s': a['M2'],
            'M3_smb_anomalo':             a['M3'],
            'M4_packet_in_por_min':       float(a['M4']),
            'M5_flujos_east_west':        'M5' in disparadas,
            'M5_count':                   a['M5_count'],
        },
        'umbrales_superados':  disparadas,
        'ioc_activados':       iocs(disparadas),
        'accion_ryu_previa':   f'OFPFlowMod DROP prioridad 100 — {ip} aislado',
        'solicitud_al_agente': '',
    }


# =============================================================================
# Preparacion
# =============================================================================

def preparar(caso: dict) -> dict:
    """
    Deja la DB como si solo hubiera ocurrido el contexto del caso y devuelve
    la alerta lista para POST /alert. Borra incidentes, bloqueos, hosts en
    riesgo y whitelist.
    """
    ahora = datetime.utcnow()
    ctx = caso.get('contexto', {})
    hace = lambda minutos: (ahora - timedelta(minutes=minutos)).isoformat() + 'Z'

    borrar_datos_de_red()
    previos = ctx.get('incidentes_previos', [])
    for inc in sorted(previos, key=lambda i: -i['minutos_antes']):
        # Un falso_positivo previo se asume desbloqueado por el operador
        sembrar_incidente(
            inc['host'], hace(inc['minutos_antes']), puntaje(inc['metricas']), inc['metricas'],
            inc['veredicto'], inc['confianza'], dpid(inc['host']),
            bloqueado=inc['veredicto'] != 'falso_positivo',
        )
    for r in ctx.get('hosts_riesgo', []):
        sembrar_host_riesgo(r['ip'], f'contactado por {r["origen"]} via SMB',
                            hace(r['minutos_antes']), r['origen'])
    for w in ctx.get('whitelist', []):
        agregar_whitelist(w['ip'], w['razon'])
    set_estado_red('nivel_alerta', ctx.get('nivel_alerta', 'NORMAL'))
    set_estado_red('incidentes_sesion', str(len(previos)))

    return construir_payload(caso['alerta'], ahora.isoformat() + 'Z')
