# -*- coding: utf-8 -*-
"""
services/reglas.py
Decisiones deterministas que antes pedia el prompt al LLM (seccion
"NIVEL DE AUTONOMIA" de services/prompt.py::SYSTEM_PROMPT): nivel de
autonomia, acciones automaticas / pendientes y nivel de alerta de la red.
Sin LLM, sin red, sin DB: funciones puras.
"""

from config import SUBNET_ADM
from services.prompt import VENTANA_PROPAGACION, _antiguedad, _parse_ts

CONFIANZA_NIVEL_1    = 85   # confirmado con esta confianza o mas -> nivel 1
EQUIPOS_NIVEL_3      = 4    # equipos afectados a partir de los cuales -> nivel 3

# Lista blanca de acciones por veredicto. Los nombres son los que reconocen
# services/agente.py::_ejecutar_nivel_1 y ::_on_aprobado.
# desbloquear_host solo se permite con falso_positivo.
ACCIONES_PERMITIDAS_POR_VEREDICTO: dict[str, frozenset[str]] = {
    'confirmado':     frozenset({'mantener_bloqueo'}),
    'ya_contenido':   frozenset({'mantener_bloqueo'}),
    'indeterminado':  frozenset({'mantener_bloqueo'}),
    'falso_positivo': frozenset({'desbloquear_host'}),
}


def es_red_administracion(ip: str) -> bool:
    return ip.startswith(SUBNET_ADM)


def equipos_afectados(
    ip_origen: str,
    hosts_en_riesgo: list[str],
    hosts_bloqueados: list[dict],
    timestamp_alerta: str,
) -> set[str]:
    """
    Host de origen + hosts_en_riesgo + hosts bloqueados dentro de la
    ventana de propagacion (VENTANA_PROPAGACION antes de la alerta).
    """
    ts_ref = _parse_ts(timestamp_alerta)
    afectados = {ip_origen, *hosts_en_riesgo}
    for h in hosts_bloqueados:
        edad = _antiguedad(h.get('timestamp', ''), ts_ref)
        if edad is not None and edad <= VENTANA_PROPAGACION:
            afectados.add(h['ip'])
    return afectados


def decidir_acciones(
    veredicto: str,
    confianza: int,
    ip_origen: str,
    n_afectados: int,
) -> dict:
    """
    Nivel 3: confirmado en la red de administracion, o 4+ equipos afectados.
             Sin acciones: solo se avisa al operador.
    Nivel 1: confirmado con confianza >= 85 (fuera de nivel 3), o ya_contenido.
             Accion automatica: mantener_bloqueo.
    Nivel 2: todo lo demas. falso_positivo -> pide aprobar desbloquear_host;
             indeterminado o confirmado < 85 -> pide aprobar mantener_bloqueo.
    """
    if (veredicto == 'confirmado' and es_red_administracion(ip_origen)) \
            or n_afectados >= EQUIPOS_NIVEL_3:
        nivel, automaticas, pendientes = 3, [], []
    elif (veredicto == 'confirmado' and confianza >= CONFIANZA_NIVEL_1) \
            or veredicto == 'ya_contenido':
        nivel, automaticas, pendientes = 1, ['mantener_bloqueo'], []
    elif veredicto == 'falso_positivo':
        nivel, automaticas, pendientes = 2, [], ['desbloquear_host']
    else:
        nivel, automaticas, pendientes = 2, [], ['mantener_bloqueo']

    permitidas = ACCIONES_PERMITIDAS_POR_VEREDICTO.get(veredicto, frozenset())
    return {
        'nivel_autonomia':                nivel,
        'acciones_automaticas':           [a for a in automaticas if a in permitidas],
        'acciones_pendientes_aprobacion': [a for a in pendientes if a in permitidas],
    }


def nivel_alerta_red(veredicto: str, nivel_actual: str) -> dict:
    """ALTO si confirmado, MEDIO si indeterminado, sin cambio en los demas casos."""
    if veredicto == 'confirmado':
        nivel = 'ALTO'
    elif veredicto == 'indeterminado':
        nivel = 'MEDIO'
    else:
        nivel = nivel_actual
    return {'nivel_alerta_red': nivel}
