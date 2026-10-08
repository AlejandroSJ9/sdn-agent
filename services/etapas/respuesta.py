# -*- coding: utf-8 -*-
"""
services/etapas/respuesta.py
Etapa 3: redactar el mensaje al operador y las recomendaciones forenses.
Recibe el veredicto, el nivel y las acciones ya decididos por el codigo:
no decide acciones y su salida no puede cambiarlas.
"""

import html

from services.esquemas import MAX_MENSAJE_TELEGRAM, MAX_RECOMENDACIONES, SalidaRespuesta, SalidaVeredicto
from services.etapas import (
    INSTRUCCION_DATOS, INSTRUCCION_SOLO_JSON, ResultadoEtapa, bloque_datos, ejecutar_etapa,
)

SYSTEM_PROMPT_RESPUESTA = f"""Redactas las notificaciones de un agente de seguridad de red para el operador del SOC.
El analisis ya termino: el veredicto, el nivel de autonomia y las acciones los decidio el
sistema. No puedes cambiarlos, ni proponer, ni anunciar otras acciones.

Tu unica tarea es redactar en espanol:
1. "mensaje_telegram": maximo {MAX_MENSAJE_TELEGRAM} caracteres. Debe decir el equipo, el veredicto,
   la confianza, lo que el sistema hizo o pide aprobar (exactamente las acciones dadas) y el
   motivo principal en una frase. Solo puedes usar las etiquetas HTML <b> y <code>.
2. "recomendaciones_forenses": de 1 a {MAX_RECOMENDACIONES} pasos concretos para investigar el equipo,
   coherentes con el veredicto:
   - confirmado o ya_contenido: preservar evidencia y buscar como se propago.
   - falso_positivo: confirmar con el responsable que la tarea estaba autorizada.
   - indeterminado: averiguar que proceso genero las conexiones.
No inventes datos que no esten en el mensaje (IPs, nombres, cifras).

{INSTRUCCION_DATOS}

{INSTRUCCION_SOLO_JSON}
{{"mensaje_telegram": "texto para el operador", "recomendaciones_forenses": ["paso 1", "paso 2"]}}"""


_TITULO = {
    'confirmado':     'Ransomware confirmado',
    'falso_positivo': 'Probable falso positivo',
    'indeterminado':  'Alerta indeterminada',
    'ya_contenido':   'Ataque ya contenido',
}

_QUE_SIGNIFICA_NIVEL = {
    1: 'el agente actua solo, sin esperar al operador',
    2: 'las acciones esperan la aprobacion del operador',
    3: 'alerta urgente: el agente no ejecuta nada y decide el operador',
}

_NOMBRE_ACCION = {
    'mantener_bloqueo': 'mantener el bloqueo',
    'desbloquear_host': 'desbloquear el equipo',
}


def _acciones_texto(acciones: list[str]) -> str:
    return ', '.join(_NOMBRE_ACCION.get(a, a) for a in acciones) or 'ninguna'


def construir_user_respuesta(payload: dict, veredicto: SalidaVeredicto, decision: dict) -> str:
    nivel = decision['nivel_autonomia']
    datos = '\n'.join([
        f'Equipo: {payload.get("host_origen", "desconocido")}',
        f'Senales que pasaron su limite: {", ".join(payload.get("umbrales_superados", []))}',
        f'Veredicto: {veredicto.veredicto}',
        f'Confianza: {veredicto.confianza}%',
        f'Severidad: {veredicto.severidad}',
        f'Nivel de autonomia: {nivel} ({_QUE_SIGNIFICA_NIVEL.get(nivel, "desconocido")})',
        f'Acciones ejecutadas automaticamente: {_acciones_texto(decision["acciones_automaticas"])}',
        f'Acciones que esperan aprobacion: {_acciones_texto(decision["acciones_pendientes_aprobacion"])}',
        f'Equipos en riesgo: {", ".join(veredicto.hosts_en_riesgo) or "ninguno"}',
        f'Razonamiento del analisis: {veredicto.razonamiento}',
    ])
    return (f'=== DECISION YA TOMADA (no la cambies) ===\n{bloque_datos(datos)}\n\n'
            f'Redacta el mensaje y las recomendaciones y responde solo con el JSON.')


def fallback_respuesta(payload: dict, veredicto: SalidaVeredicto, decision: dict) -> SalidaRespuesta:
    """Mensaje plantilla con veredicto, host, confianza y nivel."""
    nivel = decision['nivel_autonomia']
    if decision['acciones_automaticas']:
        accion = f'Accion ejecutada: {_acciones_texto(decision["acciones_automaticas"])}.'
    elif decision['acciones_pendientes_aprobacion']:
        accion = f'Se pide aprobar: {_acciones_texto(decision["acciones_pendientes_aprobacion"])}.'
    else:
        accion = 'El agente no ejecuto acciones: revisar manualmente.'
    mensaje = (
        f'<b>{_TITULO.get(veredicto.veredicto, veredicto.veredicto)}</b> -- '
        f'host <code>{html.escape(str(payload.get("host_origen", "desconocido")))}</code>\n'
        f'Confianza: {veredicto.confianza}% | Nivel de autonomia: {nivel}\n'
        f'{accion}'
    )
    return SalidaRespuesta(mensaje_telegram=mensaje,
                           recomendaciones_forenses=['Revisar manualmente el incidente'])


def ejecutar_respuesta(payload: dict, veredicto: SalidaVeredicto, decision: dict) -> ResultadoEtapa:
    return ejecutar_etapa(
        'etapa3', 'respuesta',
        SYSTEM_PROMPT_RESPUESTA, construir_user_respuesta(payload, veredicto, decision),
        SalidaRespuesta, lambda: fallback_respuesta(payload, veredicto, decision),
    )
