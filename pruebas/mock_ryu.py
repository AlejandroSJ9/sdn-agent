#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_ryu.py -- Simulador de la REST API del controlador Ryu
Universidad Catolica de Colombia -- Proyecto de Grado 2026

Simula los endpoints que el agente SDN consume:
  GET  /stats/flow/{dpid}        -- flujos activos del switch
  GET  /stats/port/{dpid}        -- estadisticas de puertos
  POST /stats/flowentry/add      -- instalar regla (DROP, rate-limit)
  POST /stats/flowentry/delete   -- eliminar regla (desbloquear host)
  GET  /v1.0/topology/switches   -- switches conectados
  GET  /v1.0/topology/hosts      -- hosts conocidos

Uso:
    python3 mock_ryu.py

El mock corre en el puerto 8080 -- el mismo que usa Ryu real.
El agente no necesita ningun cambio para usarlo.
"""

import json
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [MOCK-RYU] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('MockRyu')

# -- Estado simulado de la red -----------------------------------------------
# Registro de reglas instaladas por el agente durante las pruebas
reglas_instaladas: list[dict] = []
hosts_bloqueados:  set[str]   = set()

# -- Datos simulados ----------------------------------------------------------

def get_flujos_simulados(dpid: int) -> dict:
    """
    Simula OFPFlowStatsReply con trafico realista.
    Incluye flujos normales + flujos anomalos que activaran las metricas.
    """
    now = time.time()
    return {
        str(dpid): [
            # -- Trafico normal (ICMP ping entre hosts) ------------------------
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 45, 'duration_nsec': 0,
                'packet_count': 10, 'byte_count': 840,
                'match': {'in_port': 1, 'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.2',
                          'ip_proto': 1},
                'actions': ['OUTPUT:2'],
            },
            # -- Flujos SMB anomalos (M1 + M3) --------------------------------
            # Flujo breve y voluminoso hacia h2:445 -- firma de PsExec
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 2,        # < 5s  --> activa M3
                'byte_count': 589824,     # 576KB > 512KB --> activa M3
                'packet_count': 412,
                'match': {'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.2',
                          'ip_proto': 6, 'tcp_dst': 445},
                'actions': ['OUTPUT:2'],
            },
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 3, 'byte_count': 524800,
                'packet_count': 380,
                'match': {'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.3',
                          'ip_proto': 6, 'tcp_dst': 445},
                'actions': ['OUTPUT:3'],
            },
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 4, 'byte_count': 614400,
                'packet_count': 440,
                'match': {'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.4',
                          'ip_proto': 6, 'tcp_dst': 445},
                'actions': ['OUTPUT:4'],
            },
            # -- Flujos RDP anomalos (M1 + M5) --------------------------------
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 8, 'byte_count': 12800,
                'packet_count': 95,
                'match': {'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.5',
                          'ip_proto': 6, 'tcp_dst': 3389},
                'actions': ['OUTPUT:5'],
            },
            # -- Flujos WMI anomalos (M1 + M5) --------------------------------
            {
                'priority': 1, 'idle_timeout': 30, 'hard_timeout': 60,
                'duration_sec': 6, 'byte_count': 8400,
                'packet_count': 62,
                'match': {'dl_type': 2048,
                          'nw_src': '10.0.10.1', 'nw_dst': '10.0.10.2',
                          'ip_proto': 6, 'tcp_dst': 135},
                'actions': ['OUTPUT:2'],
            },
            # -- Regla table-miss ---------------------------------------------
            {
                'priority': 0, 'idle_timeout': 0, 'hard_timeout': 0,
                'duration_sec': 3600, 'byte_count': 89600,
                'packet_count': 1120,
                'match': {},
                'actions': ['CONTROLLER:65535'],
            },
        ]
    }


def get_puertos_simulados(dpid: int) -> dict:
    return {
        str(dpid): [
            {'port_no': i, 'rx_packets': 1200 + i*50, 'tx_packets': 1100 + i*45,
             'rx_bytes': 98000 + i*4000, 'tx_bytes': 87000 + i*3500,
             'rx_errors': 0, 'tx_errors': 0}
            for i in range(1, 7)
        ]
    }


def get_switches_simulados() -> list:
    return [
        {'dpid': '0000000000000001', 'ports': [
            {'dpid': '0000000000000001', 'port_no': i, 'name': f's1-eth{i}'}
            for i in range(1, 7)
        ]},
        {'dpid': '0000000000000002', 'ports': [
            {'dpid': '0000000000000002', 'port_no': i, 'name': f's2-eth{i}'}
            for i in range(1, 7)
        ]},
        {'dpid': '0000000000000003', 'ports': [
            {'dpid': '0000000000000003', 'port_no': i, 'name': f's3-eth{i}'}
            for i in range(1, 3)
        ]},
    ]


def get_hosts_simulados() -> list:
    hosts = []
    for i in range(1, 6):
        hosts.append({
            'mac': f'00:00:00:00:00:0{i}',
            'ipv4': [f'10.0.10.{i}'],
            'port': {'dpid': '0000000000000001', 'port_no': i},
        })
    for i in range(1, 6):
        hosts.append({
            'mac': f'00:00:00:00:00:{i+5:02x}',
            'ipv4': [f'10.0.20.{i}'],
            'port': {'dpid': '0000000000000002', 'port_no': i},
        })
    return hosts


# -- HTTP Handler -------------------------------------------------------------

class RyuMockHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # silenciar logs por defecto del HTTPServer

    def _send_json(self, data: dict | list, status: int = 200):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get('Content-Length', 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def do_GET(self):
        path = urlparse(self.path).path

        # GET /stats/flow/{dpid}
        if path.startswith('/stats/flow/'):
            dpid = int(path.split('/')[-1])
            data = get_flujos_simulados(dpid)
            logger.info(f'GET /stats/flow/{dpid} -- '
                        f'{len(data[str(dpid)])} flujos retornados')
            self._send_json(data)

        # GET /stats/port/{dpid}
        elif path.startswith('/stats/port/'):
            dpid = int(path.split('/')[-1])
            data = get_puertos_simulados(dpid)
            logger.info(f'GET /stats/port/{dpid} -- OK')
            self._send_json(data)

        # GET /v1.0/topology/switches
        elif path == '/v1.0/topology/switches':
            data = get_switches_simulados()
            logger.info(f'GET /topology/switches -- {len(data)} switches')
            self._send_json(data)

        # GET /v1.0/topology/hosts
        elif path == '/v1.0/topology/hosts':
            data = get_hosts_simulados()
            logger.info(f'GET /topology/hosts -- {len(data)} hosts')
            self._send_json(data)

        # GET /reglas (endpoint extra para ver que instalo el agente)
        elif path == '/reglas':
            self._send_json({
                'reglas_instaladas': reglas_instaladas,
                'hosts_bloqueados':  list(hosts_bloqueados),
                'total':             len(reglas_instaladas),
            })

        else:
            logger.warning(f'GET {path} -- 404 Not Found')
            self._send_json({'error': f'endpoint no encontrado: {path}'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        # POST /stats/flowentry/add -- instalar regla (DROP o rate-limit)
        if path == '/stats/flowentry/add':
            match   = body.get('match', {})
            actions = body.get('actions', [])
            ip      = match.get('nw_src', 'desconocido')
            prio    = body.get('priority', 0)
            es_drop = len(actions) == 0

            reglas_instaladas.append({
                'tipo':      'DROP' if es_drop else 'RATE-LIMIT',
                'ip':        ip,
                'priority':  prio,
                'match':     match,
                'actions':   actions,
                'timestamp': time.strftime('%H:%M:%S'),
            })

            if es_drop:
                hosts_bloqueados.add(ip)
                logger.info(f'POST /flowentry/add -- DROP instalado para {ip} '
                            f'(prioridad {prio})')
            else:
                logger.info(f'POST /flowentry/add -- rate-limit para {ip}')

            self._send_json({'result': 'OK', 'ip': ip, 'tipo': 'DROP' if es_drop else 'RATE-LIMIT'})

        # POST /stats/flowentry/delete -- eliminar regla (desbloquear host)
        elif path == '/stats/flowentry/delete':
            match = body.get('match', {})
            ip    = match.get('nw_src', 'desconocido')

            hosts_bloqueados.discard(ip)
            reglas_instaladas.append({
                'tipo':      'DELETE',
                'ip':        ip,
                'timestamp': time.strftime('%H:%M:%S'),
            })
            logger.info(f'POST /flowentry/delete -- regla eliminada para {ip}')
            self._send_json({'result': 'OK', 'ip': ip, 'tipo': 'DELETE'})

        else:
            logger.warning(f'POST {path} -- 404 Not Found')
            self._send_json({'error': f'endpoint no encontrado: {path}'}, 404)


# -- Main ---------------------------------------------------------------------

def run(host='0.0.0.0', port=8080):
    server = HTTPServer((host, port), RyuMockHandler)
    print()
    print('=' * 55)
    print('  MOCK RYU -- Simulador de REST API')
    print('=' * 55)
    print(f'  Escuchando en http://{host}:{port}')
    print()
    print('  Endpoints disponibles:')
    print(f'  GET  http://localhost:{port}/stats/flow/1')
    print(f'  GET  http://localhost:{port}/stats/port/1')
    print(f'  GET  http://localhost:{port}/v1.0/topology/switches')
    print(f'  GET  http://localhost:{port}/v1.0/topology/hosts')
    print(f'  POST http://localhost:{port}/stats/flowentry/add')
    print(f'  POST http://localhost:{port}/stats/flowentry/delete')
    print()
    print(f'  Ver reglas instaladas por el agente:')
    print(f'  GET  http://localhost:{port}/reglas')
    print('=' * 55)
    print('  Ctrl+C para detener')
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[Mock Ryu] Detenido.')


if __name__ == '__main__':
    run()