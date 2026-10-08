# -*- coding: utf-8 -*-
"""
services/prompt.py
Construccion de prompts para el agente SDN.

Python solo calcula hechos (cuanto pasa cada senal su limite, whitelist,
historial, propagacion) y los entrega en frases simples. El veredicto lo
decide el LLM comparando dos explicaciones: ataque o uso legitimo.
Las etiquetas del user prompt son las mismas que usa el system prompt.
"""

import json
from datetime import datetime, timedelta
from config import MAX_TURNOS_LLM


# Limites del controlador Ryu-IA (ryu_controller.py)
UMBRAL_M1 = 20    # conexiones nuevas a puertos sensibles en 30 s (> 20)
UMBRAL_M2 = 15    # equipos distintos contactados en 30 s (> 15)
UMBRAL_M4 = 200   # mensajes al controlador por minuto (> 200)
UMBRAL_M5 = 5     # conexiones directas entre equipos de usuario (>= 5)

VENTANA_REPETICION  = timedelta(minutes=15)
VENTANA_PROPAGACION = timedelta(minutes=30)
MAX_HISTORIAL       = 5


# DEPRECATED: prompt unico del analizador monolitico (services/monolitico.py,
# LLM_PIPELINE=monolitico). El analisis por defecto usa los prompts de
# services/etapas/. Se conserva para comparar ambas versiones en la tesis.
SYSTEM_PROMPT = """Eres un analista de seguridad de redes. Recibes alertas de una red de oficina
y decides si cada alerta es un ataque de ransomware o no.

Equivocarse en cualquier direccion es grave:
- Si llamas ataque a algo normal, se desconecta a un usuario o servidor sin motivo.
- Si llamas normal a un ataque, el ransomware se extiende a otros equipos.
  Este es el peor error.

== QUE MIDE EL SISTEMA ==
El controlador solo envia una alerta cuando 3 o mas senales pasan su limite.
SENALES FUERTES:
  M3: una copia de archivo por la red (puerto 445) muy grande y muy rapida.
  M5: un equipo se conecta directamente a otros equipos de la red por puertos
      de administracion remota (445, 135, 139, 3389, 5985). Limite: 5 equipos.
SENALES DEBILES:
  M1: conexiones nuevas a puertos sensibles en 30 segundos. Limite: 20.
  M2: equipos distintos contactados en 30 segundos. Limite: 15.
  M4: mensajes enviados al controlador de red por minuto. Limite: 200.

== LO QUE DEBES SABER ==
1. Asi se mueve el ransomware: copia su programa a otros equipos por la red y
   lo ejecuta con herramientas como PsExec, WMI o escritorio remoto (RDP).
   Eso produce M3 y M5.
2. Las herramientas de administracion legitimas producen EXACTAMENTE el mismo
   trafico: instalar software en muchos equipos, escaneres de vulnerabilidades,
   soporte tecnico remoto, scripts de PowerShell remoto. Los numeros solos no
   distinguen un ataque de una tarea de administracion.
3. Lo que los distingue es el contexto que trae el mensaje:
   - LISTA BLANCA: el equipo esta autorizado para tareas de administracion. Si
     el motivo explica el trafico de la alerta, es la mejor prueba de uso legitimo.
   - HISTORIAL DEL EQUIPO: alertas anteriores y como se resolvieron. La misma
     alerta repetida y ya revisada como falso_positivo apoya el uso legitimo.
   - RED: otros equipos confirmados como ataque hace poco, o este equipo senalado
     en riesgo por un ataque. Apoya el ataque, aunque las senales sean debiles.
4. Los atacantes tambien usan herramientas legitimas con contrasenas robadas.
   Si un equipo de la lista blanca alerta mientras hay ataques activos en la
   red, no lo descartes.

== COMO DECIDIR ==
Compara dos explicaciones con los datos del mensaje:
  A) Ataque: que datos la apoyan.
  B) Uso legitimo: que dato concreto la apoya (lista blanca o historial).
Elige el veredicto:
  confirmado:     A tiene apoyo en los datos y B no tiene ningun dato concreto.
  falso_positivo: B tiene un dato concreto que explica la alerta y no hay
                  ataques activos que lo contradigan. Nunca uses falso_positivo
                  sin un dato concreto: liberar un equipo infectado es el peor error.
  indeterminado:  los datos no permiten elegir entre A y B. El equipo sigue
                  bloqueado hasta que un operador lo revise.
  ya_contenido:   el HISTORIAL dice que esta alerta repite la de un ataque ya
                  confirmado y el equipo ya estaba bloqueado.

"razonamiento" es tu analisis real, en 4 partes cortas con los datos del caso:
(1) que apoya el ataque, (2) que apoya el uso legitimo, (3) estado de la red,
(4) veredicto y por que no es otro. Menciona solo senales que esten en SI.
Maximo 5 frases.

== CONFIANZA (0 a 100) ==
Mide que tan seguro estas del veredicto, no que tan grave es la alerta:
  90 a 100: casi seguro; todos los datos apuntan al mismo lado.
  70 a 89:  probable; hay algun dato que genera duda.
  40 a 69:  dudoso; lo normal en indeterminado.
No uses el mismo numero para todo: ajustalo a la evidencia de cada caso.

== NIVEL DE AUTONOMIA ==
  3: si el veredicto es confirmado y la linea "Red de administracion" dice SI,
     o si el ataque ya afecto a 4 o mas equipos. Solo se avisa al operador.
  1: confirmado con confianza 85 o mas (fuera de los casos de nivel 3), o
     ya_contenido. Accion: "mantener_bloqueo".
  2: todo lo demas: confirmado con confianza menor a 85; falso_positivo (pide
     aprobar "desbloquear_host"); indeterminado (pide aprobar "mantener_bloqueo").

"hosts_en_riesgo": direcciones IP del mensaje que este equipo pudo infectar,
siempre entre comillas, por ejemplo ["10.0.10.7", "10.0.10.9"]. Nunca inventes
direcciones. Si no hay, usa [].

== SI TE FALTA UN DATO ==
Puedes pedir un dato que cambiaria tu decision (maximo {max_turnos} veces):
{{"estado":"necesito_datos","solicitud":"historial_host"|"flujos_switch"|"hosts_bloqueados"|"hosts_riesgo","parametros":{{"ip":"...","dpid":1}},"razon":"..."}}

== EJEMPLOS (datos inventados; razona con los datos de tu caso, no copies) ==
{{"estado":"veredicto_final","razonamiento":"(1) M3 y M5 en SI: copio un archivo grande y se conecto a 9 equipos por puertos de administracion. (2) No esta en la lista blanca y no tiene historial. (3) Hace 6 minutos se confirmo un ataque en 10.0.10.7. (4) confirmado: nada apoya el uso legitimo.","veredicto":"confirmado","severidad":"critica","confianza":93,"nivel_autonomia":1,"acciones_automaticas":["mantener_bloqueo"],"acciones_pendientes_aprobacion":[],"hosts_en_riesgo":["10.0.10.7","10.0.10.9"],"mensaje_telegram":"Ransomware confirmado: copia rapida y conexiones a 9 equipos","recomendaciones_forenses":["Capturar memoria RAM","Revisar servicios creados recientemente"],"actualizar_estado_red":{{"nivel_alerta_red":"ALTO"}}}}
{{"estado":"veredicto_final","razonamiento":"(1) M5 en SI con 14 equipos y M1, M2 muy por encima del limite. (2) Esta en la lista blanca como servidor de copias de seguridad que se conecta a cada equipo por SMB, lo que explica este trafico. (3) No hay otros ataques en la red. (4) falso_positivo: la lista blanca explica la alerta y nada la contradice.","veredicto":"falso_positivo","severidad":"media","confianza":80,"nivel_autonomia":2,"acciones_automaticas":[],"acciones_pendientes_aprobacion":["desbloquear_host"],"hosts_en_riesgo":[],"mensaje_telegram":"Probable falsa alarma: servidor de copias autorizado. Aprobar desbloqueo","recomendaciones_forenses":["Confirmar que la tarea de copia estaba programada"],"actualizar_estado_red":{{"nivel_alerta_red":"NORMAL"}}}}
{{"estado":"veredicto_final","razonamiento":"(1) Solo senales debiles: M1, M2 y M4 apenas sobre el limite; M3 y M5 en NO. (2) No esta en la lista blanca y no tiene historial. (3) No hay otros ataques en la red. (4) indeterminado: no hay pruebas de ataque ni una explicacion legitima.","veredicto":"indeterminado","severidad":"media","confianza":50,"nivel_autonomia":2,"acciones_automaticas":[],"acciones_pendientes_aprobacion":["mantener_bloqueo"],"hosts_en_riesgo":[],"mensaje_telegram":"Alerta dudosa sin senales fuertes. Revisar el equipo","recomendaciones_forenses":["Revisar que procesos generaron las conexiones"],"actualizar_estado_red":{{"nivel_alerta_red":"MEDIO"}}}}

== FORMATO DE RESPUESTA ==
Responde solo con un objeto JSON. Sin texto antes ni despues, sin ```.
Usa las mismas claves de los ejemplos:
  estado: "veredicto_final"
  razonamiento: texto
  veredicto: "confirmado" | "falso_positivo" | "indeterminado" | "ya_contenido"
  severidad: "critica" | "alta" | "media"
  confianza: numero entero de 0 a 100
  nivel_autonomia: 1 | 2 | 3
  acciones_automaticas, acciones_pendientes_aprobacion, hosts_en_riesgo,
  recomendaciones_forenses: listas de textos entre comillas
  mensaje_telegram: texto corto para el operador
  actualizar_estado_red: {{"nivel_alerta_red": "NORMAL" | "MEDIO" | "ALTO" | "CRITICO"}}""".format(
    max_turnos=MAX_TURNOS_LLM,
)


# =============================================================================
# Hechos de la alerta
# =============================================================================

def _parse_ts(valor: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(valor).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None


def _antiguedad(ts_evento: str, ts_ref: datetime | None) -> timedelta | None:
    evento = _parse_ts(ts_evento)
    if evento is None or ts_ref is None:
        return None
    return ts_ref - evento


def _hace(delta: timedelta | None) -> str:
    if delta is None:
        return 'en fecha desconocida'
    minutos = int(delta.total_seconds() // 60)
    if minutos < 60:
        return f'hace {minutos} minutos'
    if minutos < 48 * 60:
        return f'hace {minutos // 60} horas'
    return f'hace {minutos // (24 * 60)} dias'


def _frente_al_limite(valor: float, limite: int) -> str:
    if valor <= limite:
        return 'no pasa el limite'
    veces = valor / limite
    if veces < 2:
        return f'pasa el limite por poco ({veces:.1f} veces el limite)'
    return f'pasa el limite con mucho ({veces:.1f} veces el limite)'


def hechos_alerta(
    payload: dict,
    hosts_bloqueados: list,
    hosts_en_riesgo: list,
    whitelist: dict | None = None,
    historial: list | None = None,
) -> dict:
    """
    Calcula los hechos que el LLM necesita para decidir, sin proponer
    veredicto. Funcion pura: facil de testear offline.
    """
    src_ip   = payload.get('host_origen', '')
    metricas = payload.get('metricas', {})
    ts_ref   = _parse_ts(payload.get('timestamp', ''))
    disparadas = sorted(payload.get('umbrales_superados', []))
    historial  = historial or []

    bloqueo = next((h for h in hosts_bloqueados if h.get('ip') == src_ip), None)
    riesgo  = next((h for h in hosts_en_riesgo if h.get('ip') == src_ip), None)

    # Repeticion: el ultimo incidente del equipo fue un ataque confirmado,
    # hace poco, con las mismas metricas, y el equipo sigue bloqueado.
    ultimo = historial[0] if historial else None
    edad_ultimo = _antiguedad(ultimo['timestamp'], ts_ref) if ultimo else None
    repite = bool(
        ultimo and bloqueo
        and ultimo.get('veredicto') == 'confirmado'
        and bloqueo.get('veredicto') == 'confirmado'
        and sorted(ultimo.get('metricas', [])) == disparadas
        and edad_ultimo is not None and edad_ultimo <= VENTANA_REPETICION
    )

    otros_confirmados = []
    for h in hosts_bloqueados:
        edad = _antiguedad(h.get('timestamp', ''), ts_ref)
        if (h.get('ip') != src_ip and h.get('veredicto') == 'confirmado'
                and edad is not None and edad <= VENTANA_PROPAGACION):
            otros_confirmados.append((h['ip'], edad))

    return {
        'src_ip': src_ip,
        'red_adm': src_ip.startswith('10.0.20.'),
        'disparadas': disparadas,
        'm1': metricas.get('M1_nuevos_flujos_por_30s', 0),
        'm2': metricas.get('M2_destinos_unicos_por_30s', 0),
        'm3': bool(metricas.get('M3_smb_anomalo', False)),
        'm4': metricas.get('M4_packet_in_por_min', 0),
        'm5': bool(metricas.get('M5_flujos_east_west', False)),
        'm5_count': metricas.get('M5_count', 0),
        'whitelist': whitelist,
        'historial': [(i, _antiguedad(i['timestamp'], ts_ref)) for i in historial[:MAX_HISTORIAL]],
        'total_historial': len(historial),
        'bloqueo': bloqueo,
        'repite': repite,
        'riesgo': riesgo,
        'riesgo_edad': _antiguedad(riesgo.get('timestamp', ''), ts_ref) if riesgo else None,
        'otros_confirmados': otros_confirmados,
    }


def _si_no(valor: bool) -> str:
    return 'SI' if valor else 'NO'


def construir_user_prompt(
    payload: dict,
    estado_red: dict,
    hosts_bloqueados: list,
    hosts_en_riesgo: list,
    whitelist: dict | None = None,
    historial: list | None = None,
) -> str:
    h = hechos_alerta(payload, hosts_bloqueados, hosts_en_riesgo, whitelist, historial)
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

    return f"""=== ALERTA ===
Equipo: {ip}
Red: {payload.get('contexto_topologico', 'desconocida')}
Red de administracion (VLAN ADM): {_si_no(h['red_adm'])}
Switch (dpid): {payload.get('dpid_switch', 'desconocido')}
Senales que pasaron su limite: {', '.join(h['disparadas'])}

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
Otros equipos confirmados como ataque en los ultimos 30 minutos: {linea_otros}
Nivel de alerta de la red: {estado_red.get('nivel_alerta', 'NORMAL')}

Compara las dos explicaciones (ataque o uso legitimo) y responde solo con el JSON.
"""


def construir_mensaje_datos(solicitud: str, datos: dict) -> str:
    return (
        f'Datos solicitados ({solicitud}):\n'
        f'{json.dumps(datos, indent=2, ensure_ascii=False)}'
    )


def get_system_prompt() -> str:
    """DEPRECATED: solo lo usa services/monolitico.py."""
    return SYSTEM_PROMPT
