#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_escenarios.py -- Evaluacion del agente SDN con escenarios documentados
Universidad Católica de Colombia -- Proyecto de Grado 2026

Los casos viven en escenarios.json. Cada uno describe un comportamiento real
(ataque o administracion legitima) respaldado por fuentes como CISA/FBI,
MITRE ATT&CK, Microsoft, Tenable o NIST.

Diferencias con test_flujo.py:
  - Las alertas se construyen igual que Ryu-IA (_send_json_alert): solo
    existen con 3 o mas metricas disparadas y los valores son coherentes
    con los umbrales del controlador.
  - Cada caso corre aislado: se limpia la DB y se siembra su contexto
    (whitelist, incidentes previos, hosts en riesgo, nivel de alerta).
  - Los errores pesan segun su costo: liberar un equipo comprometido
    cuesta mas que pedir revision de uno legitimo.
  - Se evalua tambien el nivel de autonomia.
  - --repeticiones y --variantes miden si el veredicto es estable.

Uso:
  python test_escenarios.py --validar                 # revisa el JSON, sin servidor
  python test_escenarios.py                           # conjunto 'desarrollo'
  python test_escenarios.py --conjunto validacion     # solo al final del ajuste
  python test_escenarios.py --repeticiones 3 --variantes 2
  python test_escenarios.py --comparar rep_a.json rep_b.json   # tabla comparativa de reportes
"""

import argparse
import json
import random
import sqlite3
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

AQUI         = Path(__file__).resolve().parent
ESCENARIOS   = AQUI / 'escenarios.json'
DB_DEFECTO   = AQUI.parent / 'sdn_context.db'
AGENTE_URL   = 'http://localhost:8081'
TIMEOUT      = 200   # segundos de espera por caso

# Umbrales y logica de Ryu-IA (ryu_controller.py)
UMBRAL_M1, UMBRAL_M2, UMBRAL_M4, UMBRAL_M5 = 20, 15, 200, 5
METRICAS_MINIMAS = 3
# El agente exige puntaje_total aunque Ryu-IA no lo envia: se calcula con
# los mismos pesos que config.METRIC_WEIGHTS para no inventar un valor.
PESOS = {'M5': 40, 'M3': 35, 'M1': 25, 'M2': 20, 'M4': 15}

CLASES     = {'ataque', 'legitimo', 'ambiguo', 'duplicado'}
VEREDICTOS = {'confirmado', 'falso_positivo', 'indeterminado', 'ya_contenido'}

# Costo de un veredicto fuera de 'aceptables', segun la clase real del caso
COSTO_ERROR = {
    ('ataque',    'falso_positivo'): 3,    # libera un equipo comprometido
    ('duplicado', 'falso_positivo'): 3,
    ('ambiguo',   'falso_positivo'): 2,    # libera sin evidencia suficiente
    ('legitimo',  'confirmado'):     2,    # aisla a un usuario legitimo
}
COSTO_DEFECTO = 1
CRITICOS = {('ataque', 'falso_positivo'), ('duplicado', 'falso_positivo')}

OK, FAIL, WARN, INFO, BOLD, END = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[1m', '\033[0m'
SEP = '─' * 65


# =============================================================================
# Construccion de alertas (replica de Ryu-IA)
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
    if {'M1', 'M2'} <= t:              out.append('IOC-01')
    if 'M3' in t:                      out.append('IOC-02')
    if 'M4' in t:                      out.append('IOC-03')
    if 'M5' in t:                      out.append('IOC-04')
    if {'M5', 'M1'} <= t:              out.append('IOC-07')
    if len(t) >= METRICAS_MINIMAS:     out.append('IOC-05')
    return sorted(set(out))


def contexto_topologico(ip: str) -> str:
    if ip.startswith('10.0.10.'):
        return 'VLAN OPS (ID=10), subred 10.0.10.0/24'
    if ip.startswith('10.0.20.'):
        return 'VLAN ADM (ID=20), subred 10.0.20.0/24'
    return 'subred desconocida'


def dpid(ip: str) -> str:
    return '0x0000000000000002' if ip.startswith('10.0.20.') else '0x0000000000000001'


def puntaje(disparadas: list[str]) -> int:
    return sum(PESOS[m] for m in disparadas)


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
        'puntaje_maximo':      sum(PESOS.values()),
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


def variante(a: dict, rng: random.Random) -> dict:
    """
    Cambia los contadores entre -15% y +15% sin cruzar ningun umbral:
    el conjunto de metricas disparadas (lo unico que define la alerta en
    Ryu-IA) queda igual, asi que el veredicto deberia ser el mismo.
    """
    v = dict(a)
    for clave, umbral, minimo in (('M1', UMBRAL_M1, 0), ('M2', UMBRAL_M2, 0), ('M4', UMBRAL_M4, 0)):
        nuevo = round(a[clave] * rng.uniform(0.85, 1.15))
        v[clave] = max(nuevo, umbral + 1) if a[clave] > umbral else min(max(nuevo, minimo), umbral)
    if a['M5_count'] >= UMBRAL_M5:
        v['M5_count'] = max(round(a['M5_count'] * rng.uniform(0.85, 1.15)), UMBRAL_M5)
    else:
        v['M5_count'] = min(round(a['M5_count'] * rng.uniform(0.85, 1.15)), UMBRAL_M5 - 1)
    return v


# =============================================================================
# Validacion del archivo de escenarios
# =============================================================================

def validar(casos: list[dict]) -> list[str]:
    errores, ids = [], set()
    for c in casos:
        cid = c.get('id', '?')
        if cid in ids:
            errores.append(f'{cid}: id repetido')
        ids.add(cid)
        if c.get('clase') not in CLASES:
            errores.append(f'{cid}: clase invalida {c.get("clase")}')
        if c.get('conjunto') not in ('desarrollo', 'validacion'):
            errores.append(f'{cid}: conjunto invalido {c.get("conjunto")}')
        esp = c.get('esperado', {})
        if esp.get('veredicto') not in VEREDICTOS:
            errores.append(f'{cid}: veredicto esperado invalido')
        if esp.get('veredicto') not in esp.get('aceptables', []):
            errores.append(f'{cid}: el veredicto esperado no esta en aceptables')
        if not set(esp.get('aceptables', [])) <= VEREDICTOS:
            errores.append(f'{cid}: aceptables con valores invalidos')
        if not esp.get('niveles') or not set(esp['niveles']) <= {1, 2, 3}:
            errores.append(f'{cid}: niveles invalidos')
        fuentes = c.get('fuentes', [])
        if not fuentes or any(not f.get('url') or not f.get('organizacion') or not f.get('dato') for f in fuentes):
            errores.append(f'{cid}: cada caso necesita fuentes con organizacion, url y dato')
        disparadas = metricas_disparadas(c['alerta'])
        if len(disparadas) < METRICAS_MINIMAS:
            errores.append(f'{cid}: solo {disparadas} disparadas; Ryu-IA no envia alertas con menos de {METRICAS_MINIMAS}')
        ctx = c.get('contexto', {})
        if c.get('clase') == 'legitimo':
            explicado = (any(w['ip'] == c['alerta']['host'] for w in ctx.get('whitelist', []))
                         or any(i['host'] == c['alerta']['host'] for i in ctx.get('incidentes_previos', [])))
            if not explicado:
                errores.append(f'{cid}: caso legitimo sin whitelist ni historial que lo haga decidible')
        if c.get('clase') == 'duplicado' and not any(
                i['host'] == c['alerta']['host'] and i['veredicto'] == 'confirmado'
                for i in ctx.get('incidentes_previos', [])):
            errores.append(f'{cid}: duplicado sin incidente confirmado previo del mismo equipo')
    return errores


# =============================================================================
# Preparacion de la DB
# =============================================================================

def preparar_db(db: Path, contexto: dict, ts_alerta: datetime) -> None:
    """Deja la DB como si solo hubiera ocurrido el contexto del caso."""
    con = sqlite3.connect(db)
    try:
        for tabla in ('incidentes', 'hosts_bloqueados', 'hosts_riesgo', 'whitelist'):
            con.execute(f'DELETE FROM {tabla}')

        previos = contexto.get('incidentes_previos', [])
        for inc in sorted(previos, key=lambda i: -i['minutos_antes']):
            ts = (ts_alerta - timedelta(minutes=inc['minutos_antes'])).isoformat() + 'Z'
            pts = puntaje(inc['metricas'])
            con.execute(
                'INSERT INTO incidentes (host, timestamp, puntaje, metricas, veredicto, '
                'confianza, nivel_auto, payload, razonamiento, error) VALUES (?,?,?,?,?,?,?,?,?,NULL)',
                (inc['host'], ts, pts, json.dumps(inc['metricas']), inc['veredicto'],
                 inc['confianza'], 2, '{}', 'Incidente sembrado por test_escenarios.py'),
            )
            # Un falso_positivo previo se asume desbloqueado por el operador
            if inc['veredicto'] != 'falso_positivo':
                con.execute(
                    'INSERT OR REPLACE INTO hosts_bloqueados (ip, timestamp, puntaje, veredicto, confianza, dpid) '
                    'VALUES (?,?,?,?,?,?)',
                    (inc['host'], ts, pts, inc['veredicto'], inc['confianza'], dpid(inc['host'])),
                )

        for r in contexto.get('hosts_riesgo', []):
            ts = (ts_alerta - timedelta(minutes=r['minutos_antes'])).isoformat() + 'Z'
            con.execute(
                'INSERT OR REPLACE INTO hosts_riesgo (ip, razon, timestamp, origen_ip) VALUES (?,?,?,?)',
                (r['ip'], f'contactado por {r["origen"]} via SMB', ts, r['origen']),
            )

        for w in contexto.get('whitelist', []):
            con.execute(
                'INSERT OR REPLACE INTO whitelist (ip, agregado, razon) VALUES (?,?,?)',
                (w['ip'], ts_alerta.isoformat(), w['razon']),
            )

        con.execute("INSERT OR REPLACE INTO estado_red VALUES ('nivel_alerta', ?)",
                    (contexto.get('nivel_alerta', 'NORMAL'),))
        con.execute("INSERT OR REPLACE INTO estado_red VALUES ('incidentes_sesion', ?)",
                    (str(len(previos)),))
        con.commit()
    finally:
        con.close()


# =============================================================================
# HTTP
# =============================================================================

def http(metodo: str, url: str, cuerpo: Optional[dict] = None, timeout: int = 10):
    datos = json.dumps(cuerpo).encode('utf-8') if cuerpo is not None else None
    req = urllib.request.Request(url, data=datos, method=metodo,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {'http_error': e.code, 'detail': e.read().decode()[:300]}
    except Exception as e:
        return {'connection_error': str(e)}


def esperar_incidente(host: str, ts: str, timeout: int) -> Optional[dict]:
    inicio = time.time()
    while time.time() - inicio < timeout:
        time.sleep(2)
        incidentes = http('GET', f'{AGENTE_URL}/incidentes?limite=20')
        if isinstance(incidentes, list):
            for inc in incidentes:
                if inc.get('host') == host and inc.get('timestamp') == ts:
                    return inc
    return None


# =============================================================================
# Ejecucion y evaluacion
# =============================================================================

def ejecutar(caso: dict, alerta: dict, db: Path, etiqueta: str) -> dict:
    ahora = datetime.utcnow()
    ts = ahora.isoformat() + 'Z'
    preparar_db(db, caso.get('contexto', {}), ahora)
    payload = construir_payload(alerta, ts)

    r = {'id': caso['id'], 'ejecucion': etiqueta, 'clase': caso['clase'],
         'conjunto': caso['conjunto'], 'alerta': alerta, 'error': '',
         'veredicto': None, 'confianza': None, 'nivel': None, 'razonamiento': '',
         'acierto': False, 'nivel_ok': False, 'confianza_ok': False, 'costo': 0,
         }

    inicio = time.time()
    resp = http('POST', f'{AGENTE_URL}/alert', payload)
    # /alert responde con el contrato de Ryu-IA: veredicto final o provisional
    if not isinstance(resp, dict) or 'veredicto' not in resp:
        r['error'] = f'El agente no acepto la alerta: {resp}'
        return r
    r['respuesta_ryu'] = resp

    inc = esperar_incidente(payload['host_origen'], ts, TIMEOUT)
    r['tiempo_s'] = round(time.time() - inicio, 1)
    if not inc:
        r['error'] = f'Timeout: el agente no registro el incidente en {TIMEOUT}s'
        return r
    r['razonamiento'] = inc.get('razonamiento') or ''
    if inc.get('error'):
        r['error'] = f'Fallback del LLM: {inc["error"]}'
        return r

    esp = caso['esperado']
    r['veredicto'], r['confianza'], r['nivel'] = inc.get('veredicto'), inc.get('confianza'), inc.get('nivel')
    r['acierto']  = r['veredicto'] in esp['aceptables']
    # El MVP no usa niveles de autonomia: nivel None no se evalua
    r['nivel_ok'] = None if r['nivel'] is None else r['nivel'] in esp['niveles']
    r['confianza_ok'] = (r['confianza'] or 0) >= esp.get('confianza_minima', 0) if r['acierto'] else False
    if not r['acierto']:
        r['costo'] = COSTO_ERROR.get((caso['clase'], r['veredicto']), COSTO_DEFECTO)
        r['critico'] = (caso['clase'], r['veredicto']) in CRITICOS
    return r


def resumir(resultados: list[dict]) -> dict:
    validos = [r for r in resultados if not r['error']]
    por_clase = {}
    for clase in sorted(CLASES):
        rs = [r for r in validos if r['clase'] == clase]
        if rs:
            por_clase[clase] = {'aciertos': sum(r['acierto'] for r in rs), 'total': len(rs)}

    # Estabilidad: en cuantas ejecuciones de un mismo caso sale el veredicto mas comun
    estabilidad = {}
    for cid in sorted({r['id'] for r in validos}):
        vs = [r['veredicto'] for r in validos if r['id'] == cid]
        comun, n = Counter(vs).most_common(1)[0]
        estabilidad[cid] = {'mas_comun': comun, 'coinciden': n, 'ejecuciones': len(vs)}

    n = len(validos)
    con_nivel = [r for r in validos if r['nivel_ok'] is not None]
    return {
        'ejecuciones':           len(resultados),
        'validas':               n,
        'errores_sistema':       len(resultados) - n,
        # Ryu solo ejecuta lo que llega en la respuesta: las provisionales
        # significan que el veredicto del LLM no llego a tiempo
        'respuestas_provisionales_ryu': sum(1 for r in resultados
                                            if r.get('respuesta_ryu', {}).get('provisional')),
        'aciertos':              sum(r['acierto'] for r in validos),
        'tasa_acierto':          round(100 * sum(r['acierto'] for r in validos) / n, 1) if n else 0,
        'costo_total':           sum(r['costo'] for r in validos),
        'costo_medio':           round(sum(r['costo'] for r in validos) / n, 2) if n else 0,
        'fallos_criticos':       sorted({r['id'] for r in validos if r.get('critico')}),
        'nivel_correcto':        (round(100 * sum(r['nivel_ok'] for r in con_nivel) / len(con_nivel), 1)
                                  if con_nivel else '-'),
        'confianza_suficiente':  sum(r['confianza_ok'] for r in validos),
        'por_clase':             por_clase,
        'estabilidad':           estabilidad,
    }


def detalle_confianza_nivel(r: dict) -> str:
    partes = [f'{r["confianza"]}%' if r['confianza'] is not None else None,
              f'nivel {r["nivel"]}' if r['nivel'] is not None else None]
    partes = [p for p in partes if p]
    return f'({", ".join(partes)})' if partes else ''


def imprimir(r: dict, caso: dict) -> None:
    esp = caso['esperado']
    if r['error']:
        print(f'  {WARN}ERROR{END} {r["id"]} [{r["ejecucion"]}] {r["error"]}')
        return
    marca = f'{OK}OK  {END}' if r['acierto'] else f'{FAIL}FALLO{END}'
    nivel = '' if r['nivel_ok'] is not False else f' {WARN}(nivel esperado {esp["niveles"]}){END}'
    print(f'  {marca} {r["id"]} [{r["ejecucion"]}] {caso["clase"]:9} '
          f'esperado={esp["veredicto"]:14} obtenido={r["veredicto"]} '
          f'{detalle_confianza_nivel(r)}{nivel}  {r.get("tiempo_s", 0)}s')
    if not r['acierto']:
        critico = f' {FAIL}CRITICO{END}' if r.get('critico') else ''
        print(f'         costo={r["costo"]}{critico} | aceptables={esp["aceptables"]}')
        print(f'         razonamiento: {r["razonamiento"]}')


def imprimir_resumen(res: dict) -> None:
    print(f'\n{"=" * 65}\n{BOLD}  RESUMEN{END}\n{"=" * 65}')
    print(f'  Ejecuciones validas:  {res["validas"]}/{res["ejecuciones"]} '
          f'(errores de sistema: {res["errores_sistema"]})')
    print(f'  Aciertos:             {res["aciertos"]}/{res["validas"]} ({res["tasa_acierto"]}%)')
    print(f'  Respuestas provisionales a Ryu: {res["respuestas_provisionales_ryu"]}/{res["ejecuciones"]}')
    print(f'  Costo total / medio:  {res["costo_total"]} / {res["costo_medio"]}')
    color = FAIL if res['fallos_criticos'] else OK
    print(f'  Fallos criticos:      {color}{res["fallos_criticos"] or "ninguno"}{END}')
    if res['nivel_correcto'] != '-':
        print(f'  Nivel correcto:       {res["nivel_correcto"]}%')
    print(f'\n  {BOLD}Por clase:{END}')
    for clase, v in res['por_clase'].items():
        print(f'    {clase:10} {v["aciertos"]}/{v["total"]}')
    inestables = {k: v for k, v in res['estabilidad'].items() if v['coinciden'] < v['ejecuciones']}
    if inestables:
        print(f'\n  {BOLD}Casos inestables (el veredicto cambia entre ejecuciones):{END}')
        for cid, v in inestables.items():
            print(f'    {cid}: {v["coinciden"]}/{v["ejecuciones"]} -> {v["mas_comun"]}')


def comparar(rutas: list[Path]) -> None:
    """Tabla comparativa de varios reportes (incluye los de versiones anteriores del agente)."""
    reportes = [json.loads(Path(r).read_text(encoding='utf-8')) for r in rutas]
    cols = [rep.get('pipeline') or rep['parametros'].get('pipeline', '?') for rep in reportes]
    filas = [
        ('Ejecuciones', lambda s: s['ejecuciones']),
        ('Validas', lambda s: s['validas']),
        ('Errores de sistema', lambda s: s['errores_sistema']),
        ('Aciertos', lambda s: f'{s["aciertos"]}/{s["validas"]}'),
        ('Tasa de acierto %', lambda s: s['tasa_acierto']),
        ('Nivel correcto %', lambda s: s['nivel_correcto']),
        ('Costo total', lambda s: s['costo_total']),
        ('Fallos criticos', lambda s: ', '.join(s['fallos_criticos']) or '-'),
        ('Respuestas provisionales', lambda s: s.get('respuestas_provisionales_ryu', '-')),
    ]
    for clase in sorted(CLASES):
        filas.append((f'Aciertos {clase}', lambda s, c=clase:
                      f'{s["por_clase"][c]["aciertos"]}/{s["por_clase"][c]["total"]}' if c in s['por_clase'] else '-'))
    claves_fb = sorted({k for rep in reportes for k in rep['resumen'].get('fallbacks_por_etapa', {})})
    for k in claves_fb:
        filas.append((f'Fallbacks {k}', lambda s, k=k: s.get('fallbacks_por_etapa', {}).get(k, '-')))
    claves_lat = sorted({k for rep in reportes for k in rep['resumen'].get('latencia_media_ms', {})})
    for k in claves_lat:
        filas.append((f'Latencia media {k} ms', lambda s, k=k: s.get('latencia_media_ms', {}).get(k, '-')))

    ancho = max(len(f[0]) for f in filas) + 2
    print(f'\n{BOLD}{"":{ancho}}' + ''.join(f'{c:>14}' for c in cols) + END)
    for nombre, fn in filas:
        print(f'{nombre:{ancho}}' + ''.join(f'{str(fn(rep["resumen"])):>14}' for rep in reportes))


def main() -> None:
    global AGENTE_URL
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--validar', action='store_true', help='solo revisa escenarios.json')
    ap.add_argument('--conjunto', choices=['desarrollo', 'validacion', 'todos'], default='desarrollo')
    ap.add_argument('--ids', nargs='*', help='ejecutar solo estos casos')
    ap.add_argument('--repeticiones', type=int, default=1, help='veces que se envia cada alerta original')
    ap.add_argument('--variantes', type=int, default=0, help='alertas extra por caso con contadores perturbados')
    ap.add_argument('--semilla', type=int, default=2026)
    ap.add_argument('--db', type=Path, default=DB_DEFECTO, help='DB que usa el agente')
    ap.add_argument('--url', default=AGENTE_URL)
    ap.add_argument('--pipeline', default='mvp',
                    help='etiqueta de la version del agente evaluada (nombre del reporte)')
    ap.add_argument('--comparar', nargs='+', type=Path, metavar='REPORTE',
                    help='imprime la tabla comparativa de estos reportes y termina')
    args = ap.parse_args()
    AGENTE_URL = args.url
    if args.comparar:
        comparar(args.comparar)
        return

    datos = json.loads(ESCENARIOS.read_text(encoding='utf-8'))
    casos = datos['casos']
    errores = validar(casos)
    if errores:
        print(f'{FAIL}escenarios.json tiene errores:{END}')
        for e in errores:
            print(f'  - {e}')
        raise SystemExit(1)
    if args.validar:
        cuenta = Counter((c['conjunto'], c['clase']) for c in casos)
        print(f'{OK}escenarios.json valido{END}: {len(casos)} casos')
        for (conj, clase), n in sorted(cuenta.items()):
            print(f'  {conj:11} {clase:10} {n}')
        return

    if args.conjunto != 'todos':
        casos = [c for c in casos if c['conjunto'] == args.conjunto]
    if args.ids:
        casos = [c for c in casos if c['id'] in args.ids]
    if not args.db.exists():
        raise SystemExit(f'No existe la DB {args.db}; usa --db con la ruta que usa el agente')

    salud = http('GET', f'{AGENTE_URL}/health')
    if not isinstance(salud, dict) or salud.get('status') != 'ok':
        raise SystemExit(f'{FAIL}El agente no responde en {AGENTE_URL}{END}: {salud}')

    print(f'\n{BOLD}EVALUACION CON ESCENARIOS{END} -- modelo: {salud.get("modelo")} '
          f'-- pipeline: {args.pipeline}')
    print(f'Conjunto: {args.conjunto} | casos: {len(casos)} | repeticiones: {args.repeticiones} '
          f'| variantes: {args.variantes} | DB: {args.db}')
    print(f'{WARN}Cada caso borra incidentes, bloqueos, hosts en riesgo y whitelist de esa DB.{END}\n{SEP}')

    rng = random.Random(args.semilla)
    resultados = []
    for caso in casos:
        ejecuciones = [(f'r{i + 1}', caso['alerta']) for i in range(args.repeticiones)]
        ejecuciones += [(f'v{i + 1}', variante(caso['alerta'], rng)) for i in range(args.variantes)]
        for etiqueta, alerta in ejecuciones:
            r = ejecutar(caso, alerta, args.db, etiqueta)
            resultados.append(r)
            imprimir(r, caso)

    resumen = resumir(resultados)
    imprimir_resumen(resumen)

    archivo = AQUI / f'reporte_escenarios_{args.pipeline}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    archivo.write_text(json.dumps({
        'timestamp': datetime.now().isoformat(),
        'modelo': salud.get('modelo'),
        'pipeline': args.pipeline,
        'parametros': {k: str(v) for k, v in vars(args).items()},
        'resumen': resumen,
        'resultados': resultados,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'\n  Reporte: {archivo}')


if __name__ == '__main__':
    main()
