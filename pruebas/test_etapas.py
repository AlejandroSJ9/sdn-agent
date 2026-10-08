#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_etapas.py -- Pruebas offline del analisis LLM en 3 etapas
Universidad Catolica de Colombia -- Proyecto de Grado 2026

No llama a OpenRouter, a Ryu ni a la DB: el LLM y el contexto se simulan.
pytest no esta en requirements.txt, asi que las pruebas son funciones
test_* con asserts simples (pytest tambien las descubre si se instala).

Uso:
  python pruebas/test_etapas.py            # todas
  python pruebas/test_etapas.py reglas     # solo las que contienen 'reglas'
"""

import json
import os
import sys
import traceback
from contextlib import contextmanager
from pathlib import Path

# config.py exige estas variables al importarse; las pruebas no las usan
os.environ.setdefault('OPENROUTER_API_KEY', 'sk-test')
os.environ['TELEGRAM_ENABLED'] = 'false'
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import reglas  # noqa: E402

TS = '2026-10-07T12:00:00Z'


@contextmanager
def parche(objeto, nombre: str, valor):
    """monkeypatch minimo: reemplaza un atributo y lo restaura al salir."""
    original = getattr(objeto, nombre)
    setattr(objeto, nombre, valor)
    try:
        yield
    finally:
        setattr(objeto, nombre, original)


# =============================================================================
# reglas.py
# =============================================================================

# (veredicto, confianza, ip_origen, n_afectados) -> (nivel, automaticas, pendientes)
CASOS_REGLAS = [
    # confirmado
    ('confirmado',     95, '10.0.10.3', 1, 1, ['mantener_bloqueo'], []),
    ('confirmado',     85, '10.0.10.3', 3, 1, ['mantener_bloqueo'], []),
    ('confirmado',     84, '10.0.10.3', 1, 2, [], ['mantener_bloqueo']),
    ('confirmado',     50, '10.0.10.3', 3, 2, [], ['mantener_bloqueo']),
    ('confirmado',     95, '10.0.20.3', 1, 3, [], []),   # red de administracion
    ('confirmado',     60, '10.0.20.3', 1, 3, [], []),
    ('confirmado',     95, '10.0.10.3', 4, 3, [], []),   # 4 equipos afectados
    ('confirmado',     60, '10.0.10.3', 5, 3, [], []),
    # ya_contenido
    ('ya_contenido',   90, '10.0.10.2', 1, 1, ['mantener_bloqueo'], []),
    ('ya_contenido',   30, '10.0.10.2', 1, 1, ['mantener_bloqueo'], []),
    ('ya_contenido',   90, '10.0.20.2', 1, 1, ['mantener_bloqueo'], []),  # ADM solo cuenta con confirmado
    ('ya_contenido',   90, '10.0.10.2', 4, 3, [], []),
    # falso_positivo
    ('falso_positivo', 95, '10.0.10.5', 1, 2, [], ['desbloquear_host']),
    ('falso_positivo', 60, '10.0.20.2', 1, 2, [], ['desbloquear_host']),
    ('falso_positivo', 95, '10.0.10.5', 4, 3, [], []),
    # indeterminado
    ('indeterminado',  50, '10.0.10.4', 1, 2, [], ['mantener_bloqueo']),
    ('indeterminado',  95, '10.0.20.4', 3, 2, [], ['mantener_bloqueo']),
    ('indeterminado',  50, '10.0.10.4', 4, 3, [], []),
]


def test_reglas_tabla_niveles_y_acciones():
    for ver, conf, ip, n, nivel, auto, pend in CASOS_REGLAS:
        d = reglas.decidir_acciones(ver, conf, ip, n)
        esperado = {'nivel_autonomia': nivel, 'acciones_automaticas': auto,
                    'acciones_pendientes_aprobacion': pend}
        assert d == esperado, f'{(ver, conf, ip, n)}: {d} != {esperado}'


def test_reglas_desbloqueo_solo_con_falso_positivo():
    for ver, permitidas in reglas.ACCIONES_PERMITIDAS_POR_VEREDICTO.items():
        assert ('desbloquear_host' in permitidas) == (ver == 'falso_positivo'), ver
    for ver in ('confirmado', 'ya_contenido', 'indeterminado'):
        for conf in (0, 84, 85, 100):
            d = reglas.decidir_acciones(ver, conf, '10.0.10.1', 1)
            assert 'desbloquear_host' not in d['acciones_automaticas'] + d['acciones_pendientes_aprobacion']


def test_reglas_nunca_desbloqueo_automatico():
    # agente.py desbloquea sin operador si 'desbloquear_host' esta en
    # acciones_automaticas; las reglas nunca lo ponen ahi
    for ver in reglas.ACCIONES_PERMITIDAS_POR_VEREDICTO:
        for conf in (0, 85, 100):
            for ip in ('10.0.10.1', '10.0.20.1'):
                for n in (1, 4):
                    d = reglas.decidir_acciones(ver, conf, ip, n)
                    assert 'desbloquear_host' not in d['acciones_automaticas']


def test_reglas_nombres_de_accion_reconocidos_por_agente():
    fuente = (Path(__file__).resolve().parent.parent / 'services' / 'agente.py').read_text(encoding='utf-8')
    for permitidas in reglas.ACCIONES_PERMITIDAS_POR_VEREDICTO.values():
        for accion in permitidas:
            assert f"accion == '{accion}'" in fuente, f'agente.py no reconoce {accion}'


def test_reglas_equipos_afectados_ventana_propagacion():
    bloqueados = [
        {'ip': '10.0.10.1', 'timestamp': '2026-10-07T11:34:00Z'},   # hace 26 min -> cuenta
        {'ip': '10.0.10.2', 'timestamp': '2026-10-07T11:00:00Z'},   # hace 60 min -> no
        {'ip': '10.0.10.3', 'timestamp': '2026-10-07T11:55:00Z'},   # hace 5 min -> cuenta
        {'ip': '10.0.10.9', 'timestamp': 'fecha rota'},             # sin fecha -> no
    ]
    af = reglas.equipos_afectados('10.0.10.5', ['10.0.10.7', '10.0.10.3'], bloqueados, TS)
    assert af == {'10.0.10.5', '10.0.10.7', '10.0.10.1', '10.0.10.3'}, af
    # el origen ya bloqueado no se cuenta dos veces
    af = reglas.equipos_afectados('10.0.10.3', [], bloqueados, TS)
    assert af == {'10.0.10.3', '10.0.10.1'}, af


def test_reglas_nivel_alerta_red():
    assert reglas.nivel_alerta_red('confirmado', 'NORMAL') == {'nivel_alerta_red': 'ALTO'}
    assert reglas.nivel_alerta_red('indeterminado', 'NORMAL') == {'nivel_alerta_red': 'MEDIO'}
    assert reglas.nivel_alerta_red('falso_positivo', 'NORMAL') == {'nivel_alerta_red': 'NORMAL'}
    assert reglas.nivel_alerta_red('ya_contenido', 'CRITICO') == {'nivel_alerta_red': 'CRITICO'}


# =============================================================================
# Runner sin pytest
# =============================================================================

def main() -> None:
    filtro = sys.argv[1] if len(sys.argv) > 1 else ''
    pruebas = [(n, f) for n, f in globals().items()
               if n.startswith('test_') and callable(f) and filtro in n]
    fallos = 0
    for nombre, fn in pruebas:
        try:
            fn()
            print(f'  OK    {nombre}')
        except Exception:
            fallos += 1
            print(f'  FALLO {nombre}')
            traceback.print_exc()
    print(f'\n{len(pruebas) - fallos}/{len(pruebas)} pruebas pasan')
    raise SystemExit(1 if fallos else 0)


if __name__ == '__main__':
    main()
