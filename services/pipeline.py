# -*- coding: utf-8 -*-
"""
services/pipeline.py
Orquesta el analisis LLM en 3 etapas:

  1. triage    (LLM)  -> que consultas de contexto pedir
                        el codigo resuelve las consultas
  2. veredicto (LLM)  -> confirmado | falso_positivo | indeterminado | ya_contenido
                        services/reglas.py decide nivel y acciones
  3. respuesta (LLM)  -> mensaje al operador + recomendaciones forenses

Devuelve el mismo dict que el analizador anterior (services/monolitico.py)
mas 'traza_etapas'. Solo decide: las acciones las ejecuta services/agente.py.
"""

import logging
import time
from collections import deque

from config import LLM_PIPELINE
from db.repository import (
    get_historial_host, get_hosts_bloqueados, get_hosts_riesgo,
    get_estado_red, esta_en_whitelist, get_whitelist,
)
from integrations.ryu_rest import get_flujos, get_puertos
from services import reglas
from services.esquemas import CONSULTAS_VALIDAS
from services.etapas.triage import ejecutar_triage
from services.etapas.veredicto import ejecutar_veredicto, fallback_veredicto
from services.etapas.respuesta import ejecutar_respuesta, fallback_respuesta

logger = logging.getLogger('AgenteSDN.pipeline')

# Contexto minimo que distingue un ataque de un uso legitimo: se consulta
# aunque el triage no lo pida. hosts_bloqueados ademas lo necesitan
# reglas.equipos_afectados y la deteccion de ya_contenido.
CONSULTAS_SIEMPRE = ('historial_host', 'hosts_riesgo', 'hosts_bloqueados')

# Ultimas trazas por incidente, para las pruebas (GET /trazas)
_TRAZAS: deque = deque(maxlen=200)


# =============================================================================
# Resolucion de solicitudes de datos
# =============================================================================

def resolver_solicitud(solicitud: str, parametros: dict) -> dict:
    if solicitud == 'historial_host':
        ip = parametros.get('ip', '')
        historial = get_historial_host(ip)
        datos = {
            'ip':                 ip,
            'incidentes_previos': len(historial),
            'primer_incidente':   len(historial) == 0,
            'en_whitelist':       esta_en_whitelist(ip),
            'historial':          historial,
        }
        logger.info(f'[LLM] Datos resueltos (historial_host): '
                    f'{len(historial)} incidentes previos para {ip}')
        return datos
    elif solicitud == 'flujos_switch':
        dpid = parametros.get('dpid', 1)
        flujos = get_flujos(dpid)
        n = len(flujos.get(str(dpid), []))
        logger.info(f'[LLM] Datos resueltos (flujos_switch): {n} flujos en DPID={dpid}')
        return {'dpid': dpid, 'flujos': flujos}
    elif solicitud == 'estado_puertos':
        dpid = parametros.get('dpid', 1)
        return {'dpid': dpid, 'puertos': get_puertos(dpid)}
    elif solicitud == 'hosts_bloqueados':
        hosts = get_hosts_bloqueados()
        logger.info(f'[LLM] Datos resueltos (hosts_bloqueados): {len(hosts)} hosts')
        return {'hosts': hosts}
    elif solicitud == 'hosts_riesgo':
        hosts = get_hosts_riesgo()
        logger.info(f'[LLM] Datos resueltos (hosts_riesgo): {len(hosts)} hosts')
        return {'hosts': hosts}
    return {'error': f'Solicitud desconocida: {solicitud}'}


def _dpid(payload: dict) -> int:
    # Import diferido: services.agente importa este modulo
    from services.agente import _dpid_from_payload
    return _dpid_from_payload(payload)


def resolver_contexto(payload: dict, consultas: list[str]) -> dict:
    """Estado de red y whitelist siempre; una clave por consulta resuelta."""
    src_ip = payload.get('host_origen', '')
    parametros = {'ip': src_ip, 'dpid': _dpid(payload)}
    contexto = {
        'estado_red': get_estado_red(),
        'whitelist':  get_whitelist(src_ip),
    }
    for consulta in CONSULTAS_VALIDAS:
        if consulta in consultas:
            contexto[consulta] = resolver_solicitud(consulta, parametros)
    return contexto


# =============================================================================
# Analisis en 3 etapas
# =============================================================================

def analizar_por_etapas(payload: dict) -> dict:
    src_ip = payload.get('host_origen', 'desconocido')
    logger.info(f'[Pipeline] INICIO -- host={src_ip} puntaje={payload.get("puntaje_total")} '
                f'metricas={payload.get("umbrales_superados")}')
    traza: dict = {}
    errores: list[str] = []

    try:
        # -- Etapa 1: triage ------------------------------------------------
        r1 = ejecutar_triage(payload)
        traza['triage'] = r1.traza()
        consultas = sorted(set(r1.salida.consultas) | set(CONSULTAS_SIEMPRE))
        traza['consultas'] = {'pedidas': list(r1.salida.consultas), 'resueltas': consultas}
        contexto = resolver_contexto(payload, consultas)

        # -- Etapa 2: veredicto ---------------------------------------------
        r2 = ejecutar_veredicto(payload, contexto)
        traza['veredicto'] = r2.traza()
        v = r2.salida

        # -- Reglas deterministas -------------------------------------------
        afectados = reglas.equipos_afectados(
            src_ip, v.hosts_en_riesgo,
            contexto['hosts_bloqueados']['hosts'], payload.get('timestamp', ''),
        )
        decision = reglas.decidir_acciones(v.veredicto, v.confianza, src_ip, len(afectados))
        traza['reglas'] = {'equipos_afectados': sorted(afectados), **decision}

        # -- Etapa 3: respuesta ---------------------------------------------
        r3 = ejecutar_respuesta(payload, v, decision)
        traza['respuesta'] = r3.traza()
        texto = r3.salida

        errores = [f'{r.etapa}: {r.error}' for r in (r1, r2, r3) if r.fallback]
        nivel_actual = contexto['estado_red'].get('nivel_alerta', 'NORMAL')

    except Exception as e:
        # Fallo fuera de las etapas (DB, Ryu...): veredicto conservador
        logger.error(f'[Pipeline] Error en el analisis de {src_ip}: {e}', exc_info=True)
        errores.append(f'pipeline: {type(e).__name__}: {str(e)[:200]}')
        v = fallback_veredicto()
        decision = reglas.decidir_acciones(v.veredicto, v.confianza, src_ip, 1)
        texto = fallback_respuesta(payload, v, decision)
        nivel_actual = 'ALTO'

    resultado = {
        'estado':                         'veredicto_final',
        'veredicto':                      v.veredicto,
        'severidad':                      v.severidad,
        'confianza':                      v.confianza,
        'nivel_autonomia':                decision['nivel_autonomia'],
        'razonamiento':                   v.razonamiento,
        'acciones_automaticas':           decision['acciones_automaticas'],
        'acciones_pendientes_aprobacion': decision['acciones_pendientes_aprobacion'],
        'hosts_en_riesgo':                v.hosts_en_riesgo,
        'mensaje_telegram':               texto.mensaje_telegram,
        'recomendaciones_forenses':       texto.recomendaciones_forenses,
        'actualizar_estado_red':          reglas.nivel_alerta_red(v.veredicto, nivel_actual),
        'traza_etapas':                   traza,
    }
    if errores:
        resultado['error'] = '; '.join(errores)

    logger.info(
        f'[Pipeline] FIN -- {src_ip}: veredicto={v.veredicto} confianza={v.confianza}% '
        f'nivel={decision["nivel_autonomia"]} error={resultado.get("error")}'
    )
    return resultado


def _guardar_traza(payload: dict, pipeline: str, resultado: dict, latencia_ms: int) -> None:
    _TRAZAS.append({
        'host':        payload.get('host_origen'),
        'timestamp':   payload.get('timestamp'),
        'pipeline':    pipeline,
        'latencia_ms': latencia_ms,
        'error':       resultado.get('error'),
        'traza':       resultado.get('traza_etapas', {}),
    })


def get_trazas() -> list[dict]:
    return list(_TRAZAS)


def analizar_incidente(payload: dict) -> dict:
    """Punto de entrada de services/agente.py. LLM_PIPELINE elige el analizador."""
    inicio = time.monotonic()
    if LLM_PIPELINE == 'monolitico':
        # Import diferido: services.monolitico importa resolver_solicitud de aqui
        from services.monolitico import analizar_incidente as analizar_monolitico
        resultado = analizar_monolitico(payload)
    else:
        resultado = analizar_por_etapas(payload)
    _guardar_traza(payload, LLM_PIPELINE, resultado, round((time.monotonic() - inicio) * 1000))
    return resultado
