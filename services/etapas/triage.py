# -*- coding: utf-8 -*-
"""
services/etapas/triage.py
Etapa 1: elegir que consultas de contexto hacen falta para decidir.
"""

from services.esquemas import CONSULTAS_VALIDAS, SalidaTriage
from services.etapas import (
    INSTRUCCION_DATOS, INSTRUCCION_SOLO_JSON, ResultadoEtapa, bloque_datos, ejecutar_etapa,
)

SYSTEM_PROMPT_TRIAGE = f"""Eres el primer paso del analisis de una alerta de seguridad en una red SDN de oficina.
Tu unica tarea es elegir que datos de contexto hacen falta para decidir despues si la
alerta es un ataque de ransomware o uso legitimo. No decides el veredicto.

Consultas disponibles:
- historial_host: alertas anteriores del equipo y si esta en la lista blanca.
- flujos_switch: flujos activos en el switch del equipo (destinos, puertos, bytes).
- estado_puertos: contadores de trafico de los puertos del switch.
- hosts_bloqueados: equipos ya aislados en la red y su veredicto.
- hosts_riesgo: equipos senalados como posiblemente infectados por otro ataque.

Como elegir:
- Pide flujos_switch si necesitas ver a que equipos y puertos se conecto (M3 o M5 en la alerta).
- Pide hosts_bloqueados si ataques recientes en otros equipos cambiarian la decision.
- Pide estado_puertos solo si sospechas un volumen de trafico anomalo en el switch.
- Pide solo lo que cambiaria la decision.

{INSTRUCCION_DATOS}

{INSTRUCCION_SOLO_JSON}
"consultas" solo puede contener: {', '.join(CONSULTAS_VALIDAS)}.
{{"consultas": ["historial_host", "hosts_riesgo"], "razon": "texto corto"}}"""


def construir_user_triage(payload: dict) -> str:
    metricas = payload.get('metricas', {})
    alerta = '\n'.join([
        f'Equipo: {payload.get("host_origen", "desconocido")}',
        f'Red: {payload.get("contexto_topologico", "desconocida")}',
        f'Switch (dpid): {payload.get("dpid_switch", "desconocido")}',
        f'Senales que pasaron su limite: {", ".join(payload.get("umbrales_superados", []))}',
        f'Valores: M1={metricas.get("M1_nuevos_flujos_por_30s", 0)} '
        f'M2={metricas.get("M2_destinos_unicos_por_30s", 0)} '
        f'M3={"SI" if metricas.get("M3_smb_anomalo") else "NO"} '
        f'M4={metricas.get("M4_packet_in_por_min", 0)} '
        f'M5={metricas.get("M5_count", 0)} equipos',
        f'Indicadores (IOC): {", ".join(payload.get("ioc_activados", [])) or "ninguno"}',
        f'Accion previa del controlador: {payload.get("accion_ryu_previa", "")}',
        f'Solicitud del controlador: {payload.get("solicitud_al_agente") or "ninguna"}',
    ])
    return f'=== ALERTA ===\n{bloque_datos(alerta)}\n\nElige las consultas y responde solo con el JSON.'


def fallback_triage() -> SalidaTriage:
    return SalidaTriage(consultas=list(CONSULTAS_VALIDAS),
                        razon='Fallback: se piden todas las consultas.')


def ejecutar_triage(payload: dict) -> ResultadoEtapa:
    return ejecutar_etapa(
        'etapa1', 'triage',
        SYSTEM_PROMPT_TRIAGE, construir_user_triage(payload),
        SalidaTriage, fallback_triage,
    )
