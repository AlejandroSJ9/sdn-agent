#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_agente_riguroso.py -- Suite de pruebas de calidad del Agente SDN
Universidad Católica de Colombia -- Proyecto de Grado 2026

Metodología:
  - 20 casos de prueba con veredicto esperado conocido
  - Métricas: Precision, Recall, F1-Score, Accuracy
  - Detección de falsos positivos y falsos negativos
  - Matriz de confusión
  - Tiempo de respuesta por escenario
  - Reporte de calidad exportado a JSON

Categorías de prueba:
  ATAQUE REAL     → veredicto esperado: confirmado
  FALSO POSITIVO  → veredicto esperado: falso_positivo
  BORDE           → casos limítrofes en el umbral
  PROPAGACION     → cadena de hosts comprometidos
  YA CONTENIDO    → host ya bloqueado anteriormente
"""

import json
import time
import statistics
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

AGENTE_URL = 'http://localhost:8081'
TIMEOUT    = 200  # segundos por prueba

# Colores
OK    = '\033[92m'
FAIL  = '\033[91m'
WARN  = '\033[93m'
INFO  = '\033[94m'
BOLD  = '\033[1m'
END   = '\033[0m'
SEP   = '─' * 65


# =============================================================================
# Modelos de datos
# =============================================================================

@dataclass
class CasoPrueba:
    id:                  str
    nombre:              str
    categoria:           str   # ATAQUE_REAL | FALSO_POSITIVO | BORDE | PROPAGACION | YA_CONTENIDO
    descripcion:         str
    payload:             dict
    veredicto_esperado:  str   # confirmado | falso_positivo | indeterminado | ya_contenido
    nivel_autonomia_esp: int   # 1 | 2 | 3
    confianza_minima:    int   # confianza minima aceptable (0-100)
    justificacion:       str   # por que se espera ese veredicto


@dataclass
class ResultadoPrueba:
    caso:                CasoPrueba
    veredicto_obtenido:  Optional[str]  = None
    confianza_obtenida:  int            = 0
    nivel_obtenido:      int            = 0
    tiempo_ms:           float          = 0.0
    paso:                bool           = False
    razon_fallo:         str            = ''
    razonamiento_llm:    str            = ''
    error:               str            = ''


# =============================================================================
# HTTP helpers
# =============================================================================

def post(url: str, body: dict, timeout: int = TIMEOUT) -> Optional[dict]:
    try:
        data = json.dumps(body).encode('utf-8')
        req  = urllib.request.Request(
            url, data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {'http_error': e.code, 'detail': e.read().decode()}
    except Exception as e:
        return {'connection_error': str(e)}


def get(url: str, timeout: int = 10) -> Optional[dict]:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def ts() -> str:
    return datetime.utcnow().isoformat() + 'Z'


# =============================================================================
# Definición de los 20 casos de prueba
# =============================================================================

def build_casos() -> list[CasoPrueba]:
    return [

        # ── ATAQUES REALES (veredicto esperado: confirmado) ───────────────────

        CasoPrueba(
            id='AR-01',
            nombre='Ataque Ryuk completo -- todas las metricas',
            categoria='ATAQUE_REAL',
            descripcion='Host con M1+M2+M3+M5 activas, puntaje maximo 120/135',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.1', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 120, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 47, 'M2_destinos_unicos_por_30s': 23,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 310.0,
                    'M5_flujos_east_west': True, 'M5_count': 12,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20, 'M3': 35, 'M5': 40},
                'umbrales_superados': ['M1', 'M2', 'M3', 'M5'],
                'ioc_activados': ['IOC-01', 'IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=1,
            confianza_minima=85,
            justificacion='Puntaje 120 con M3+M5 activas -- firma inequivoca de Ryuk',
        ),

        CasoPrueba(
            id='AR-02',
            nombre='Deposicion de payload PsExec -- M3+M5',
            categoria='ATAQUE_REAL',
            descripcion='Flujo SMB de 580KB en 2.1s + 5 conexiones W2W',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.3', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 75, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 4, 'M2_destinos_unicos_por_30s': 2,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 12.0,
                    'M5_flujos_east_west': True, 'M5_count': 5,
                },
                'pesos_metricas': {'M3': 35, 'M5': 40},
                'umbrales_superados': ['M3', 'M5'],
                'ioc_activados': ['IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=1,
            confianza_minima=80,
            justificacion='M3+M5 es la firma mas especifica del movimiento lateral de Ryuk',
        ),

        CasoPrueba(
            id='AR-03',
            nombre='Escaneo masivo interno -- M1+M2',
            categoria='ATAQUE_REAL',
            descripcion='47 flujos nuevos en 30s hacia 23 destinos distintos',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.4', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 65, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 47, 'M2_destinos_unicos_por_30s': 23,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 18.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': ['IOC-01'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=2,
            confianza_minima=65,
            justificacion='Escaneo interno masivo es reconocimiento previo al ataque',
        ),

        CasoPrueba(
            id='AR-04',
            nombre='IP Spoofing flood -- M4 critica',
            categoria='ATAQUE_REAL',
            descripcion='1200 Packet-In por minuto desde un solo host',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.5', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 80, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 28, 'M2_destinos_unicos_por_30s': 18,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 1200.0,
                    'M5_flujos_east_west': True, 'M5_count': 3,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20, 'M4': 15},
                'umbrales_superados': ['M1', 'M2', 'M4'],
                'ioc_activados': ['IOC-01', 'IOC-03'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=1,
            confianza_minima=75,
            justificacion='M4 en 1200/min es un flood activo que satura el plano de control',
        ),

        CasoPrueba(
            id='AR-05',
            nombre='Movimiento lateral RDP directo -- M5',
            categoria='ATAQUE_REAL',
            descripcion='8 conexiones RDP directas entre workstations',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.2', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 65, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 8, 'M2_destinos_unicos_por_30s': 4,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 45.0,
                    'M5_flujos_east_west': True, 'M5_count': 8,
                },
                'pesos_metricas': {'M5': 40, 'M1': 25},
                'umbrales_superados': ['M5', 'M1'],
                'ioc_activados': ['IOC-04', 'IOC-06'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=1,
            confianza_minima=80,
            justificacion='Conexiones RDP W2W son imposibles en operacion normal',
        ),

        CasoPrueba(
            id='AR-06',
            nombre='Ataque en VLAN ADM -- host administrativo comprometido',
            categoria='ATAQUE_REAL',
            descripcion='Host de administracion comprometido intenta propagarse',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.20.3', 'dpid_switch': '0x0000000000000002',
                'contexto_topologico': 'VLAN ADM (ID=20), subred 10.0.20.0/24',
                'puntaje_total': 95, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 32, 'M2_destinos_unicos_por_30s': 19,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 87.0,
                    'M5_flujos_east_west': True, 'M5_count': 7,
                },
                'pesos_metricas': {'M1': 25, 'M3': 35, 'M5': 40},
                'umbrales_superados': ['M1', 'M3', 'M5'],
                'ioc_activados': ['IOC-01', 'IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=3,
            confianza_minima=85,
            justificacion='Host ADM comprometido es critico -- acceso privilegiado en riesgo',
        ),

        # ── FALSOS POSITIVOS (veredicto esperado: falso_positivo) ─────────────

        CasoPrueba(
            id='FP-01',
            nombre='Servidor de backup -- escaneo legitimo M1+M2',
            categoria='FALSO_POSITIVO',
            descripcion='Servidor de backup nocturno genera alto volumen de conexiones SMB',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.8', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 45, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 22, 'M2_destinos_unicos_por_30s': 16,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 28.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': ['IOC-01'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='falso_positivo',
            nivel_autonomia_esp=2,
            confianza_minima=60,
            justificacion='Sin M3 ni M5, solo M1+M2 pueden ser backup. Puntaje 45 es limítrofe',
        ),

        CasoPrueba(
            id='FP-02',
            nombre='Agente de inventario Nmap -- escaneo autorizado',
            categoria='FALSO_POSITIVO',
            descripcion='Herramienta de inventario genera fan-out masivo de destinos',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.9', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 45, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 18, 'M2_destinos_unicos_por_30s': 25,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 42.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': ['IOC-01'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='falso_positivo',
            nivel_autonomia_esp=2,
            confianza_minima=60,
            justificacion='Alto fan-out sin M3/M5 es caracteristico de herramientas de inventario',
        ),

        CasoPrueba(
            id='FP-03',
            nombre='Transferencia masiva de archivos legitima',
            categoria='FALSO_POSITIVO',
            descripcion='Usuario transfiere proyecto grande via SMB -- volumen alto pero duracion normal',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.6', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 60, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 6, 'M2_destinos_unicos_por_30s': 2,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 15.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': [],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='falso_positivo',
            nivel_autonomia_esp=2,
            confianza_minima=55,
            justificacion='Puntaje exactamente en 60, sin M3 ni M5 -- posible actividad legitima',
        ),

        # ── CASOS BORDE (veredicto esperado: indeterminado) ───────────────────

        CasoPrueba(
            id='BD-01',
            nombre='Puntaje exactamente en umbral critico -- 60 puntos',
            categoria='BORDE',
            descripcion='Solo M1+M2 superadas, puntaje justo en el limite',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.7', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 60, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 21, 'M2_destinos_unicos_por_30s': 16,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 0.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': ['IOC-01'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='indeterminado',
            nivel_autonomia_esp=2,
            confianza_minima=0,
            justificacion='Puntaje limítrofe sin metricas de alta especificidad',
        ),

        CasoPrueba(
            id='BD-02',
            nombre='M4 sola -- flood ambiguo',
            categoria='BORDE',
            descripcion='Solo M4 disparada, podria ser congestion de red no maliciosa',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.20.1', 'dpid_switch': '0x0000000000000002',
                'contexto_topologico': 'VLAN ADM (ID=20), subred 10.0.20.0/24',
                'puntaje_total': 60, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 3, 'M2_destinos_unicos_por_30s': 2,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 250.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M4': 15},
                'umbrales_superados': ['M4'],
                'ioc_activados': ['IOC-03'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='indeterminado',
            nivel_autonomia_esp=2,
            confianza_minima=0,
            justificacion='M4 sola tiene especificidad baja -- multiples causas no maliciosas',
        ),

        CasoPrueba(
            id='BD-03',
            nombre='M5 con solo 5 conexiones -- umbral justo',
            categoria='BORDE',
            descripcion='Exactamente 5 flujos W2W -- en el umbral de M5',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.10', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 65, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 6, 'M2_destinos_unicos_por_30s': 3,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 22.0,
                    'M5_flujos_east_west': True, 'M5_count': 5,
                },
                'pesos_metricas': {'M5': 40, 'M1': 25},
                'umbrales_superados': ['M5', 'M1'],
                'ioc_activados': ['IOC-04'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='indeterminado',
            nivel_autonomia_esp=2,
            confianza_minima=0,
            justificacion='M5 en umbral exacto sin M3 -- ambiguo, requiere mas contexto',
        ),

        # ── PROPAGACION EN CADENA ─────────────────────────────────────────────

        CasoPrueba(
            id='PR-01',
            nombre='Propagacion -- segundo host en cadena',
            categoria='PROPAGACION',
            descripcion='h2 se compromete despues de que h1 fue bloqueado',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.2', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 75, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 6, 'M2_destinos_unicos_por_30s': 3,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 28.0,
                    'M5_flujos_east_west': True, 'M5_count': 3,
                },
                'pesos_metricas': {'M1': 25, 'M3': 35, 'M5': 40},
                'umbrales_superados': ['M1', 'M3', 'M5'],
                'ioc_activados': ['IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=2,
            confianza_minima=85,
            justificacion='Patron de propagacion -- el agente debe reconocer el contexto de h1',
        ),

        CasoPrueba(
            id='PR-02',
            nombre='Propagacion masiva -- 5 hosts en 10 minutos',
            categoria='PROPAGACION',
            descripcion='Quinto host comprometido -- patron de propagacion masiva confirmado',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.5', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 100, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 38, 'M2_destinos_unicos_por_30s': 4,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 180.0,
                    'M5_flujos_east_west': True, 'M5_count': 9,
                },
                'pesos_metricas': {'M1': 25, 'M3': 35, 'M5': 40},
                'umbrales_superados': ['M1', 'M3', 'M5'],
                'ioc_activados': ['IOC-01', 'IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=3,
            confianza_minima=90,
            justificacion='Con 4 hosts previos bloqueados, el 5to debe activar nivel 3',
        ),

        # ── YA CONTENIDO ──────────────────────────────────────────────────────

        CasoPrueba(
            id='YC-01',
            nombre='Host ya bloqueado -- alerta duplicada de Ryu',
            categoria='YA_CONTENIDO',
            descripcion='Ryu envia segunda alerta del mismo host ya bloqueado',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.1', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 120, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 8, 'M2_destinos_unicos_por_30s': 4,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 45.0,
                    'M5_flujos_east_west': True, 'M5_count': 5,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20, 'M3': 35, 'M5': 40},
                'umbrales_superados': ['M1', 'M2', 'M3', 'M5'],
                'ioc_activados': ['IOC-01', 'IOC-02', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='ya_contenido',
            nivel_autonomia_esp=1,
            confianza_minima=90,
            justificacion='El host ya fue bloqueado -- el agente debe reconocerlo del contexto',
        ),

        # ── ATAQUES REALES ADICIONALES ────────────────────────────────────────

        CasoPrueba(
            id='AR-07',
            nombre='WMI lateral movement -- puerto 135',
            categoria='ATAQUE_REAL',
            descripcion='Ejecucion remota via WMI desde workstation',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.3', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 70, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 12, 'M2_destinos_unicos_por_30s': 8,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 55.0,
                    'M5_flujos_east_west': True, 'M5_count': 6,
                },
                'pesos_metricas': {'M1': 25, 'M5': 40},
                'umbrales_superados': ['M1', 'M5'],
                'ioc_activados': ['IOC-04', 'IOC-07'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=1,
            confianza_minima=75,
            justificacion='Conexiones WMI W2W son firma de ejecucion remota maliciosa',
        ),

        CasoPrueba(
            id='AR-08',
            nombre='Ataque con puntaje maximo -- 135 puntos',
            categoria='ATAQUE_REAL',
            descripcion='Todas las metricas en valores maximos simultaneamente',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.4', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 135, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 80, 'M2_destinos_unicos_por_30s': 45,
                    'M3_smb_anomalo': True, 'M4_packet_in_por_min': 1500.0,
                    'M5_flujos_east_west': True, 'M5_count': 20,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20, 'M3': 35, 'M4': 15, 'M5': 40},
                'umbrales_superados': ['M1', 'M2', 'M3', 'M4', 'M5'],
                'ioc_activados': ['IOC-01', 'IOC-02', 'IOC-03', 'IOC-04', 'IOC-05'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='confirmado',
            nivel_autonomia_esp=3,
            confianza_minima=95,
            justificacion='Puntaje maximo absoluto -- ataque confirmado con certeza maxima',
        ),

        CasoPrueba(
            id='FP-04',
            nombre='Primera conexion VPN -- falsa alarma M4',
            categoria='FALSO_POSITIVO',
            descripcion='Usuario conecta VPN por primera vez generando Packet-In masivo',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.20.5', 'dpid_switch': '0x0000000000000002',
                'contexto_topologico': 'VLAN ADM (ID=20), subred 10.0.20.0/24',
                'puntaje_total': 60, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 14, 'M2_destinos_unicos_por_30s': 8,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 220.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20, 'M4': 15},
                'umbrales_superados': ['M1', 'M2', 'M4'],
                'ioc_activados': ['IOC-01', 'IOC-03'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='falso_positivo',
            nivel_autonomia_esp=2,
            confianza_minima=55,
            justificacion='Sin M3 ni M5, patron compatible con primera conexion VPN',
        ),

        CasoPrueba(
            id='BD-04',
            nombre='Puntaje 61 -- un punto sobre el umbral',
            categoria='BORDE',
            descripcion='Caso extremadamente limítrofe -- un solo punto sobre el umbral critico',
            payload={
                'timestamp': ts(), 'alerta_nivel': 'CRITICO',
                'host_origen': '10.0.10.11', 'dpid_switch': '0x0000000000000001',
                'contexto_topologico': 'VLAN OPS (ID=10), subred 10.0.10.0/24',
                'puntaje_total': 61, 'puntaje_maximo': 135,
                'metricas': {
                    'M1_nuevos_flujos_por_30s': 22, 'M2_destinos_unicos_por_30s': 17,
                    'M3_smb_anomalo': False, 'M4_packet_in_por_min': 0.0,
                    'M5_flujos_east_west': False, 'M5_count': 0,
                },
                'pesos_metricas': {'M1': 25, 'M2': 20},
                'umbrales_superados': ['M1', 'M2'],
                'ioc_activados': ['IOC-01'],
                'accion_ryu_previa': 'OFPFlowMod DROP prioridad 100',
            },
            veredicto_esperado='indeterminado',
            nivel_autonomia_esp=2,
            confianza_minima=0,
            justificacion='Puntaje mínimo critico sin metricas de alta especificidad',
        ),
    ]


# =============================================================================
# Motor de pruebas
# =============================================================================

def esperar_procesamiento(payload: dict, timeout: int = TIMEOUT) -> Optional[dict]:
    """
    Espera a que el agente registre el incidente de ESTE payload en la DB.
    Se identifica por host + timestamp: buscar solo por host devolvia
    incidentes de casos o corridas anteriores con la misma IP.
    """
    host, timestamp = payload['host_origen'], payload['timestamp']
    inicio = time.time()
    while time.time() - inicio < timeout:
        time.sleep(2)
        incidentes = get(f'{AGENTE_URL}/incidentes?limite=50')
        if incidentes:
            for inc in incidentes:
                if inc.get('host') == host and inc.get('timestamp') == timestamp:
                    return inc
    return None


def ejecutar_caso(caso: CasoPrueba) -> ResultadoPrueba:
    resultado = ResultadoPrueba(caso=caso)
    inicio    = time.time()

    try:
        # Enviar alerta al agente
        resp = post(f'{AGENTE_URL}/alert', caso.payload, timeout=10)
        # /alert responde a Ryu con su contrato: veredicto (o provisional)
        if not resp or 'veredicto' not in resp:
            resultado.error = f'El agente no aceptó el payload: {resp}'
            resultado.tiempo_ms = (time.time() - inicio) * 1000
            return resultado

        # Esperar procesamiento en background
        incidente = esperar_procesamiento(caso.payload)
        resultado.tiempo_ms = (time.time() - inicio) * 1000

        if not incidente:
            resultado.error = f'Timeout -- el agente no registro el incidente en {TIMEOUT}s'
            return resultado

        resultado.razonamiento_llm = incidente.get('razonamiento') or ''

        # El agente guardo el veredicto de fallback: el LLM no respondio
        if incidente.get('error'):
            resultado.error = f'Fallback del LLM -- {incidente["error"]}'
            return resultado

        resultado.veredicto_obtenido = incidente.get('veredicto', '')
        resultado.confianza_obtenida = incidente.get('confianza', 0)
        resultado.nivel_obtenido     = incidente.get('nivel', 0)

        # Evaluar si paso la prueba
        veredicto_ok  = resultado.veredicto_obtenido == caso.veredicto_esperado
        confianza_ok  = resultado.confianza_obtenida >= caso.confianza_minima

        # Para indeterminado, la confianza puede ser 0 -- siempre OK
        if caso.veredicto_esperado == 'indeterminado':
            confianza_ok = True

        resultado.paso = veredicto_ok and confianza_ok

        if not veredicto_ok:
            resultado.razon_fallo = (
                f'Veredicto: esperado="{caso.veredicto_esperado}" '
                f'obtenido="{resultado.veredicto_obtenido}"'
            )
        elif not confianza_ok:
            resultado.razon_fallo = (
                f'Confianza insuficiente: {resultado.confianza_obtenida}% '
                f'< minimo {caso.confianza_minima}%'
            )

    except Exception as e:
        resultado.error     = str(e)
        resultado.tiempo_ms = (time.time() - inicio) * 1000

    return resultado


# =============================================================================
# Métricas de calidad
# =============================================================================

def calcular_metricas(resultados: list[ResultadoPrueba]) -> dict:
    """
    Calcula métricas de clasificacion binaria:
      TP = ataque real detectado correctamente como confirmado
      TN = no-ataque clasificado correctamente como falso_positivo o indeterminado
      FP = no-ataque clasificado incorrectamente como confirmado (falso positivo)
      FN = ataque real clasificado incorrectamente como no-confirmado (falso negativo)
    """
    TP = FP = TN = FN = 0
    errores = []

    for r in resultados:
        if r.error or not r.veredicto_obtenido:
            errores.append(r.caso.id)
            continue

        esperado  = r.caso.veredicto_esperado
        obtenido  = r.veredicto_obtenido
        es_ataque = esperado == 'confirmado'
        detectado = obtenido == 'confirmado'

        if es_ataque and detectado:      TP += 1
        elif es_ataque and not detectado: FN += 1
        elif not es_ataque and detectado: FP += 1
        else:                             TN += 1

    total = TP + TN + FP + FN
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)
    accuracy  = (TP + TN) / total if total > 0 else 0

    return {
        'TP': TP, 'FP': FP, 'TN': TN, 'FN': FN,
        'precision':       round(precision * 100, 1),
        'recall':          round(recall * 100, 1),
        'f1_score':        round(f1 * 100, 1),
        'accuracy':        round(accuracy * 100, 1),
        'tasa_fp':         round(FP / (FP + TN) * 100, 1) if (FP + TN) > 0 else 0,
        'tasa_fn':         round(FN / (FN + TP) * 100, 1) if (FN + TP) > 0 else 0,
        'errores_sistema': errores,
    }


def calcular_tiempos(resultados: list[ResultadoPrueba]) -> dict:
    tiempos = [r.tiempo_ms for r in resultados if r.tiempo_ms > 0]
    if not tiempos:
        return {}
    return {
        'promedio_ms': round(statistics.mean(tiempos), 0),
        'mediana_ms':  round(statistics.median(tiempos), 0),
        'minimo_ms':   round(min(tiempos), 0),
        'maximo_ms':   round(max(tiempos), 0),
        'p95_ms':      round(sorted(tiempos)[int(len(tiempos) * 0.95)], 0),
    }


# =============================================================================
# Reporte
# =============================================================================

def imprimir_resultado(r: ResultadoPrueba, num: int, total: int):
    icono = f'{OK}PASS{END}' if r.paso else f'{FAIL}FAIL{END}'
    print(f'\n[{num:02d}/{total}] {icono} {BOLD}{r.caso.id}{END} — {r.caso.nombre}')
    print(f'         Categoria:  {r.caso.categoria}')
    print(f'         Esperado:   {r.caso.veredicto_esperado} '
          f'(confianza min: {r.caso.confianza_minima}%)')
    if r.error:
        print(f'         {FAIL}Error:{END}      {r.error}')
    elif r.veredicto_obtenido:
        color = OK if r.paso else FAIL
        print(f'         Obtenido:   {color}{r.veredicto_obtenido}{END} '
              f'({r.confianza_obtenida}% confianza) '
              f'nivel={r.nivel_obtenido}')
        print(f'         Tiempo:     {r.tiempo_ms:.0f}ms')
        if r.razon_fallo:
            print(f'         {FAIL}Fallo:{END}      {r.razon_fallo}')
            if r.razonamiento_llm:
                print(f'         Razonamiento: {r.razonamiento_llm}')
    print(f'         Host:       {r.caso.payload["host_origen"]}  '
          f'puntaje={r.caso.payload["puntaje_total"]}')


def imprimir_reporte_final(resultados: list[ResultadoPrueba],
                           metricas: dict, tiempos: dict):
    pasaron = sum(1 for r in resultados if r.paso)
    total   = len(resultados)
    errores = sum(1 for r in resultados if r.error)

    print(f'\n\n{"=" * 65}')
    print(f'{BOLD}  REPORTE DE CALIDAD -- AGENTE SDN{END}')
    print(f'  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('=' * 65)

    # Resultado general
    color = OK if pasaron / total >= 0.8 else (WARN if pasaron / total >= 0.6 else FAIL)
    print(f'\n  {BOLD}Resultado general:{END} {color}{pasaron}/{total} pruebas pasaron{END}')
    if errores:
        print(f'  {WARN}Errores de sistema: {errores} pruebas no pudieron ejecutarse{END}')

    # Matriz de confusion
    print(f'\n  {BOLD}Matriz de confusión:{END}')
    tp = metricas['TP']; fn = metricas['FN']
    fp = metricas['FP']; tn = metricas['TN']
    print(f'  {"":20} {"Predicho: Ataque":20} {"Predicho: No-Ataque":20}')
    print(f'  {"Real: Ataque":20} {f"TP = {tp}":20} {f"FN = {fn}":20}')
    print(f'  {"Real: No-Ataque":20} {f"FP = {fp}":20} {f"TN = {tn}":20}')

    # Metricas de clasificacion
    print(f'\n  {BOLD}Métricas de clasificación:{END}')
    def color_metrica(val, umbral_ok=80, umbral_warn=60):
        if val >= umbral_ok: return f'{OK}{val}%{END}'
        if val >= umbral_warn: return f'{WARN}{val}%{END}'
        return f'{FAIL}{val}%{END}'

    print(f'  Precision:    {color_metrica(metricas["precision"])}  '
          f'(de los "confirmado" que dijo, cuántos eran reales)')
    print(f'  Recall:       {color_metrica(metricas["recall"])}  '
          f'(de los ataques reales, cuántos detectó)')
    print(f'  F1-Score:     {color_metrica(metricas["f1_score"])}  '
          f'(balance entre precision y recall)')
    print(f'  Accuracy:     {color_metrica(metricas["accuracy"])}  '
          f'(aciertos totales)')
    print(f'  Tasa FP:      {color_metrica(100 - metricas["tasa_fp"])}  '
          f'(falsos positivos: {metricas["tasa_fp"]}%)')
    print(f'  Tasa FN:      {color_metrica(100 - metricas["tasa_fn"])}  '
          f'(falsos negativos: {metricas["tasa_fn"]}%)')

    # Tiempos
    if tiempos:
        print(f'\n  {BOLD}Tiempos de respuesta:{END}')
        print(f'  Promedio: {tiempos.get("promedio_ms", 0):.0f}ms')
        print(f'  Mediana:  {tiempos.get("mediana_ms", 0):.0f}ms')
        print(f'  P95:      {tiempos.get("p95_ms", 0):.0f}ms')
        print(f'  Min/Max:  {tiempos.get("minimo_ms", 0):.0f}ms / {tiempos.get("maximo_ms", 0):.0f}ms')

    # Resumen por categoria
    print(f'\n  {BOLD}Resultado por categoría:{END}')
    categorias = {}
    for r in resultados:
        cat = r.caso.categoria
        if cat not in categorias:
            categorias[cat] = {'total': 0, 'pasaron': 0}
        categorias[cat]['total'] += 1
        if r.paso:
            categorias[cat]['pasaron'] += 1
    for cat, vals in categorias.items():
        p = vals['pasaron']
        t = vals['total']
        color = OK if p == t else (WARN if p >= t * 0.5 else FAIL)
        print(f'  {cat:20} {color}{p}/{t}{END}')

    # Fallos detallados
    fallos = [r for r in resultados if not r.paso and not r.error]
    if fallos:
        print(f'\n  {BOLD}Casos fallidos:{END}')
        for r in fallos:
            print(f'  {FAIL}✗{END} {r.caso.id} — {r.caso.nombre}')
            print(f'    Esperado: {r.caso.veredicto_esperado} | '
                  f'Obtenido: {r.veredicto_obtenido} ({r.confianza_obtenida}%)')
            print(f'    Motivo: {r.razon_fallo}')

    if errores:
        print(f'\n  {BOLD}Errores de sistema:{END}')
        for r in resultados:
            if r.error:
                print(f'  {WARN}⚠{END} {r.caso.id} — {r.error}')

    # Calificacion final
    print(f'\n{"=" * 65}')
    acc = metricas['accuracy']
    if acc >= 85:
        cal = f'{OK}EXCELENTE{END}'
    elif acc >= 70:
        cal = f'{WARN}ACEPTABLE{END}'
    else:
        cal = f'{FAIL}INSUFICIENTE{END}'
    print(f'  Calificación final: {cal} (accuracy={metricas["accuracy"]}%)')
    print('=' * 65)


def exportar_json(resultados: list[ResultadoPrueba],
                  metricas: dict, tiempos: dict):
    reporte = {
        'timestamp':  datetime.now().isoformat(),
        'total':      len(resultados),
        'pasaron':    sum(1 for r in resultados if r.paso),
        'metricas':   metricas,
        'tiempos':    tiempos,
        'casos': [
            {
                'id':                r.caso.id,
                'nombre':            r.caso.nombre,
                'categoria':         r.caso.categoria,
                'veredicto_esp':     r.caso.veredicto_esperado,
                'veredicto_obt':     r.veredicto_obtenido,
                'confianza_min':     r.caso.confianza_minima,
                'confianza_obt':     r.confianza_obtenida,
                'nivel_obtenido':    r.nivel_obtenido,
                'paso':              r.paso,
                'tiempo_ms':         r.tiempo_ms,
                'razon_fallo':       r.razon_fallo,
                'razonamiento_llm':  r.razonamiento_llm,
                'error':             r.error,
            }
            for r in resultados
        ],
    }
    fname = f'reporte_calidad_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(fname, 'w', encoding='utf-8') as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)
    print(f'\n  Reporte exportado: {fname}')
    return fname


# =============================================================================
# MAIN
# =============================================================================

def main():
    print(f'\n{"=" * 65}')
    print(f'{BOLD}  SUITE DE PRUEBAS DE CALIDAD -- AGENTE SDN{END}')
    print(f'  Universidad Católica de Colombia -- 2026')
    print('=' * 65)

    # Verificar que el agente está corriendo
    health = get(f'{AGENTE_URL}/health')
    if not health or health.get('status') != 'ok':
        print(f'\n{FAIL}El agente no está corriendo en {AGENTE_URL}{END}')
        print('Arrancar con: uvicorn main:app --host 0.0.0.0 --port 8081')
        return

    print(f'\n{OK}Agente conectado{END} — modelo: {health.get("modelo")}')
    print(f'{INFO}Ejecutando 20 casos de prueba...{END}')
    print(f'{WARN}Tiempo estimado: 8-12 minutos (cada caso espera la respuesta del LLM){END}\n')

    casos     = build_casos()
    resultados: list[ResultadoPrueba] = []

    for i, caso in enumerate(casos, 1):
        print(f'{SEP}')
        print(f'{INFO}Ejecutando [{i:02d}/{len(casos)}]: {caso.id} — {caso.nombre}{END}')
        resultado = ejecutar_caso(caso)
        resultados.append(resultado)
        imprimir_resultado(resultado, i, len(casos))

    # Calcular métricas finales
    metricas = calcular_metricas(resultados)
    tiempos  = calcular_tiempos(resultados)

    # Reporte final
    imprimir_reporte_final(resultados, metricas, tiempos)

    # Exportar JSON
    exportar_json(resultados, metricas, tiempos)


if __name__ == '__main__':
    main()