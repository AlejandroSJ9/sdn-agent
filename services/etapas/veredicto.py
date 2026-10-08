# -*- coding: utf-8 -*-
"""
services/etapas/veredicto.py
Etapa 2: comparar ataque contra uso legitimo y emitir el veredicto.
El conocimiento del dominio viene del SYSTEM_PROMPT de services/prompt.py
(QUE MIDE EL SISTEMA, LO QUE DEBES SABER, COMO DECIDIR, CONFIANZA); el
nivel de autonomia y las acciones los decide services/reglas.py.
"""

import json
import re

from services.esquemas import SalidaVeredicto
from services.etapas import (
    INSTRUCCION_DATOS, INSTRUCCION_SOLO_JSON, ResultadoEtapa, bloque_datos, ejecutar_etapa,
)
from services.prompt import (
    UMBRAL_M1, UMBRAL_M2, UMBRAL_M4, UMBRAL_M5,
    hechos_alerta, _frente_al_limite, _hace, _si_no,
)

SYSTEM_PROMPT_VEREDICTO = f"""Eres un analista de seguridad de redes. Decides si una alerta de una red de oficina
es un ataque de ransomware o uso legitimo. Liberar un equipo infectado es el peor error;
aislar sin motivo a un usuario legitimo tambien es grave.

== QUE MIDE EL SISTEMA == (la alerta solo llega con 3 o mas senales en SI)
Fuertes: M3 copia de archivo grande y rapida por la red (puerto 445).
         M5 conexiones directas a otros equipos por puertos de administracion remota
         (445, 135, 139, 3389, 5985). Limite: 5 equipos.
Debiles: M1 conexiones nuevas a puertos sensibles (limite 20 en 30 s); M2 equipos
         distintos contactados (limite 15 en 30 s); M4 mensajes al controlador (limite 200/min).

== LO QUE DEBES SABER ==
1. El ransomware copia su programa a otros equipos y lo ejecuta con PsExec, WMI o RDP: produce M3 y M5.
2. La administracion legitima (instalar software, escaneres, soporte remoto, PowerShell remoto)
   produce el mismo trafico. Los numeros solos no distinguen un ataque de una tarea de administracion.
3. Lo que los distingue es el contexto: LISTA BLANCA con un motivo que explique el trafico;
   HISTORIAL con la misma alerta ya revisada como falso_positivo; RED con ataques confirmados
   hace poco o este equipo senalado en riesgo (apoya el ataque aunque las senales sean debiles).
4. Los atacantes usan herramientas legitimas con contrasenas robadas: si un equipo de la lista
   blanca alerta mientras hay ataques activos en la red, no lo descartes.

== COMO DECIDIR ==
Compara A) ataque: que datos lo apoyan, y B) uso legitimo: que dato concreto lo apoya.
  confirmado:     A tiene apoyo en los datos y B no tiene ningun dato concreto.
  falso_positivo: un dato concreto (lista blanca o historial) explica la alerta y no hay ataques
                  activos que lo contradigan. Nunca sin ese dato: copialo en "evidencia_legitima".
  indeterminado:  los datos no permiten elegir entre A y B. El equipo sigue bloqueado.
  ya_contenido:   el HISTORIAL dice que repite un ataque ya confirmado y el equipo ya estaba bloqueado.

== CONFIANZA (0 a 100) == que tan seguro estas del veredicto, no la gravedad de la alerta:
90-100 casi seguro; 70-89 probable con alguna duda; 40-69 dudoso (lo normal en indeterminado).
"hosts_en_riesgo": solo IPs que aparecen en los datos y que este equipo pudo infectar; si no hay, [].

{INSTRUCCION_DATOS}

{INSTRUCCION_SOLO_JSON}
{{"veredicto": "confirmado | falso_positivo | indeterminado | ya_contenido", "confianza": 0, "severidad": "baja | media | alta | critica", "razonamiento": "max. 5 frases: (1) que apoya el ataque (2) que apoya el uso legitimo (3) estado de la red (4) por que este veredicto", "evidencia_legitima": "dato concreto de lista blanca o historial, o null", "hosts_en_riesgo": ["10.0.10.x"]}}"""


_IP = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')


def _lineas_flujos(datos: dict) -> str:
    """Resume los flujos de Ryu (OFPFlowStats) en una linea por flujo IP."""
    flujos = datos.get('flujos', {})
    if not isinstance(flujos, dict) or 'error' in flujos:
        return json.dumps(flujos, ensure_ascii=False)
    lineas = []
    for lista in flujos.values():
        for f in lista if isinstance(lista, list) else []:
            m = f.get('match', {})
            if not m.get('nw_src'):
                continue
            puerto = m.get('tcp_dst') or m.get('tp_dst')
            lineas.append(
                f'- {m["nw_src"]} -> {m.get("nw_dst", "?")}'
                f'{f" puerto {puerto}" if puerto else ""}: '
                f'{f.get("byte_count", 0)} bytes en {f.get("duration_sec", 0)} s'
            )
    return '\n'.join(lineas) or 'Sin flujos IP.'


def construir_user_veredicto(payload: dict, contexto: dict) -> str:
    """
    contexto: salida de services/pipeline.py::resolver_contexto
    (estado_red, whitelist y una clave por consulta resuelta).
    """
    bloqueados = contexto.get('hosts_bloqueados', {}).get('hosts', [])
    riesgo     = contexto.get('hosts_riesgo', {}).get('hosts', [])
    historial  = contexto.get('historial_host', {}).get('historial', [])
    h  = hechos_alerta(payload, bloqueados, riesgo, contexto.get('whitelist'), historial)
    ip = h['src_ip']

    if h['whitelist']:
        linea_whitelist = f'SI. Motivo registrado: "{h["whitelist"].get("razon") or "sin motivo"}".'
    else:
        linea_whitelist = 'NO.'

    if h['historial']:
        lineas = [f'{h["total_historial"]} alerta(s) anterior(es). Las mas recientes:']
        for inc, edad in h['historial']:
            lineas.append(f'- {_hace(edad)}: {inc.get("veredicto")} '
                          f'(senales: {", ".join(inc.get("metricas", [])) or "sin dato"})')
        linea_historial = '\n'.join(lineas)
    else:
        linea_historial = 'Sin alertas anteriores.'

    if h['bloqueo']:
        linea_bloqueo = (f'SI, como "{h["bloqueo"].get("veredicto")}". '
                         f'Esta alerta repite la de un ataque confirmado hace menos de 15 minutos, '
                         f'con las mismas senales: {_si_no(h["repite"])}.')
    else:
        linea_bloqueo = 'NO.'

    if h['riesgo']:
        linea_riesgo = (f'SI: {h["riesgo"].get("origen") or "otro equipo"} pudo infectarlo '
                        f'({_hace(h["riesgo_edad"])}).')
    else:
        linea_riesgo = 'NO.'

    otros = h['otros_confirmados']
    linea_otros = (f'{len(otros)}: ' + ', '.join(f'{o_ip} ({_hace(edad)})' for o_ip, edad in otros)
                   if otros else '0.')
    otros_riesgo = sorted({r['ip'] for r in riesgo if r.get('ip') != ip})

    secciones = [f"""=== ALERTA ===
Equipo: {ip}
Red: {payload.get('contexto_topologico', 'desconocida')}
Red de administracion (VLAN ADM): {_si_no(h['red_adm'])}
Switch (dpid): {payload.get('dpid_switch', 'desconocido')}
Senales que pasaron su limite: {', '.join(h['disparadas'])}
Solicitud del controlador: {payload.get('solicitud_al_agente') or 'ninguna'}

=== SENALES FUERTES ===
M3 copia de archivo grande y rapida: {_si_no(h['m3'])}
M5 conexiones directas a otros equipos: {_si_no(h['m5'])} ({h['m5_count']} equipos, limite {UMBRAL_M5})

=== SENALES DEBILES ===
M1 conexiones nuevas a puertos sensibles en 30 s: {h['m1']} (limite {UMBRAL_M1}) -> {_frente_al_limite(h['m1'], UMBRAL_M1)}
M2 equipos distintos contactados en 30 s: {h['m2']} (limite {UMBRAL_M2}) -> {_frente_al_limite(h['m2'], UMBRAL_M2)}
M4 mensajes al controlador por minuto: {h['m4']:g} (limite {UMBRAL_M4}) -> {_frente_al_limite(h['m4'], UMBRAL_M4)}

=== LISTA BLANCA ===
{ip} esta en la lista blanca: {linea_whitelist}

=== HISTORIAL DEL EQUIPO ===
{linea_historial}
{ip} ya estaba bloqueado por una alerta anterior: {linea_bloqueo}

=== RED ===
{ip} fue senalado en riesgo por un ataque: {linea_riesgo}
Otros equipos senalados en riesgo: {', '.join(otros_riesgo) or 'ninguno'}.
Otros equipos confirmados como ataque en los ultimos 30 minutos: {linea_otros}
Nivel de alerta de la red: {contexto.get('estado_red', {}).get('nivel_alerta', 'NORMAL')}"""]

    if 'flujos_switch' in contexto:
        secciones.append(f'=== FLUJOS DEL SWITCH ===\n{_lineas_flujos(contexto["flujos_switch"])}')
    if 'estado_puertos' in contexto:
        secciones.append('=== PUERTOS DEL SWITCH ===\n'
                         + json.dumps(contexto['estado_puertos'], ensure_ascii=False))

    return (bloque_datos('\n\n'.join(secciones))
            + '\n\nCompara las dos explicaciones (ataque o uso legitimo) y responde solo con el JSON.')


def ips_en_texto(texto: str) -> set[str]:
    return set(_IP.findall(texto))


def fallback_veredicto() -> SalidaVeredicto:
    return SalidaVeredicto(
        veredicto='indeterminado', confianza=0, severidad='alta',
        razonamiento='Fallback conservador de la etapa de veredicto -- revisar logs.',
        evidencia_legitima=None, hosts_en_riesgo=[],
    )


def ejecutar_veredicto(payload: dict, contexto: dict) -> ResultadoEtapa:
    user = construir_user_veredicto(payload, contexto)
    return ejecutar_etapa(
        'etapa2', 'veredicto',
        SYSTEM_PROMPT_VEREDICTO, user,
        SalidaVeredicto, fallback_veredicto,
        contexto={'ips_conocidas': ips_en_texto(user),
                  'ip_origen': payload.get('host_origen')},
    )
