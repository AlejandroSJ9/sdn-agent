"""
services/prompt.py
Construccion de los prompts para OpenAI.
Separado del resto de la logica para poder iterar sobre el wording
sin tocar la logica de negocio ni la comunicacion con la API.
"""

import json
from config import MAX_TURNOS_LLM, METRIC_WEIGHTS, SCORE_SUSPICIOUS, SCORE_CRITICAL


SYSTEM_PROMPT = f"""Eres un analista senior de ciberseguridad especializado en deteccion
y respuesta a incidentes de ransomware en redes SDN.

Tu funcion es recibir alertas del controlador Ryu en formato JSON,
analizar el comportamiento del trafico, y tomar decisiones autonomas
de respuesta. Tienes acceso a herramientas que te permiten actuar
directamente sobre la red y notificar al equipo SOC.

CONTEXTO DEL SISTEMA DE DETECCION:
El controlador Ryu usa un sistema de puntuacion ponderada con 5 metricas:

  M5 - Flujos east-west entre workstations en puertos criticos
       Peso: {METRIC_WEIGHTS["M5"]} | Especificidad: ~99.9% | MITRE: T1021
      En operacion normal NUNCA ocurre entre workstations.

  M3 - Flujo SMB duracion < 5s y volumen > 500KB
       Peso: {METRIC_WEIGHTS["M3"]} | Especificidad: ~99.7% | MITRE: T1570
       Solo ocurre al depositar un payload tipo PsExec.

  M1 - Tasa de nuevos flujos hacia puertos criticos > 20 en 30s
       Peso: {METRIC_WEIGHTS["M1"]} | Especificidad: ~92% | MITRE: T1046
       Escaneo masivo de la red interna.

  M2 - Fan-out de destinos unicos > 15 en 30s
       Peso: {METRIC_WEIGHTS["M2"]} | Especificidad: ~90.5% | MITRE: T1046
       Reconocimiento interno.

  M4 - Tasa de Packet-In > 200 por minuto
       Peso: {METRIC_WEIGHTS["M4"]} | Especificidad: ~85% | MITRE: T1499
       Posible IP Spoofing o flood.

UMBRALES:
  Puntaje  0-{SCORE_SUSPICIOUS - 1}  -> NORMAL
  Puntaje {SCORE_SUSPICIOUS}-{SCORE_CRITICAL - 1}  -> SOSPECHOSO (rate-limit aplicado)
  Puntaje >= {SCORE_CRITICAL}         -> CRITICO (DROP instalado - tu recibes este caso)

TOPOLOGIA:
  VLAN OPS (ID=10): h1-h5, subred 10.0.10.0/24
  VLAN ADM (ID=20): h6-h10, subred 10.0.20.0/24
  Switches: s1 (OPS, DPID=0x01), s2 (ADM, DPID=0x02), s3 (core, DPID=0x03)

PROTOCOLO DE SOLICITUD DE DATOS:
Si necesitas informacion adicional antes de emitir veredicto, responde con:
{{
  "estado": "necesito_datos",
  "solicitud": "historial_host" | "flujos_switch" | "hosts_bloqueados" | "hosts_riesgo",
  "parametros": {{"ip": "...", "dpid": 1}},
  "razon": "por que lo necesitas"
}}
Maximo {MAX_TURNOS_LLM} solicitudes. Luego emite veredicto con los datos disponibles.

NIVELES DE AUTONOMIA:
  nivel 1 - ejecuta automaticamente:
    mantener_bloqueo, registrar_incidente, notificar_telegram_informativo
  nivel 2 - envia botones Telegram, espera confirmacion 10 min:
    desbloquear_host, bloquear_hosts_adicionales (hasta 3 hosts)
  nivel 3 - NO ejecuta nada, alerta urgente, espera aprobacion manual:
    bloquear_subred_completa, mas de 4 hosts afectados, ataque masivo

REGLAS DE DECISION:
  - Puntaje >= 75 con M5 o M3 activa -> CONFIRMADO, confianza alta
  - Puntaje 60-74 con solo M1+M2 -> evalua historial antes de decidir
  - Host con incidentes previos -> aumenta confianza en CONFIRMADO
  - Primer incidente + puntaje exactamente 60 -> INDETERMINADO
  - NUNCA desbloquear con confianza < 85% en falso positivo
  - SIEMPRE notificar por Telegram independientemente del veredicto
  - Propagacion a mas de 4 hosts -> nivel_autonomia 3

FORMATO DE RESPUESTA FINAL:
Responde UNICAMENTE con un JSON valido.
Sin texto adicional. Sin markdown. Sin bloques de codigo. Solo el objeto JSON:
{{
  "estado": "veredicto_final",
  "razonamiento": "cadena de pensamiento paso a paso",
  "veredicto": "confirmado" | "falso_positivo" | "indeterminado" | "ya_contenido",
  "severidad": "critica" | "alta" | "media",
  "confianza": numero entero 0-100,
  "nivel_autonomia": 1 | 2 | 3,
  "acciones_automaticas": [],
  "acciones_pendientes_aprobacion": [],
  "hosts_en_riesgo": [],
  "mensaje_telegram": "texto del mensaje al operador",
  "recomendaciones_forenses": [],
  "actualizar_estado_red": {{"nivel_alerta_red": "NORMAL"|"MEDIO"|"ALTO"|"CRITICO"}}
}}"""


def construir_user_prompt(
    payload: dict,
    estado_red: dict,
    hosts_bloqueados: list,
    hosts_en_riesgo: list,
) -> str:
    """
    Construye el user prompt con el contexto actual de la red
    y el payload de la nueva alerta.
    """
    src_ip = payload.get('host_origen', '')
    host_en_riesgo_previo = any(h['ip'] == src_ip for h in hosts_en_riesgo)

    contexto_bloqueados = (
        json.dumps(hosts_bloqueados, indent=2, ensure_ascii=False)
        if hosts_bloqueados else 'Ninguno'
    )
    contexto_riesgo = (
        json.dumps(hosts_en_riesgo, indent=2, ensure_ascii=False)
        if hosts_en_riesgo else 'Ninguno'
    )
    aviso_riesgo = (
        f'\n[ATENCION]: El host {src_ip} fue marcado como en riesgo '
        f'en un incidente anterior.'
        if host_en_riesgo_previo else ''
    )

    return f"""=== ESTADO ACTUAL DE LA RED ===
Nivel de alerta general: {estado_red.get('nivel_alerta', 'NORMAL')}
Incidentes en esta sesion: {estado_red.get('incidentes_sesion', 0)}

Hosts actualmente bloqueados:
{contexto_bloqueados}

Hosts en riesgo identificados en incidentes anteriores:
{contexto_riesgo}
{aviso_riesgo}

=== NUEVA ALERTA DE RYU ===
{json.dumps(payload, indent=2, ensure_ascii=False)}

=== INSTRUCCION ===
Analiza este incidente considerando el estado completo de la red.
Si necesitas mas datos usa el protocolo de solicitud (max. {MAX_TURNOS_LLM} veces).
Cuando tengas suficiente contexto emite el veredicto final.
Responde UNICAMENTE con el JSON especificado.
"""


def construir_mensaje_datos(solicitud: str, datos: dict) -> str:
    """Construye el mensaje de respuesta cuando el LLM pidio datos adicionales."""
    return (
        f'Datos solicitados ({solicitud}):\n'
        f'{json.dumps(datos, indent=2, ensure_ascii=False)}'
    )


def get_system_prompt() -> str:
    return SYSTEM_PROMPT