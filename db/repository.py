"""
db/repository.py
Unica capa que escribe SQL. Ningun otro archivo del proyecto
debe contener queries directas a SQLite.
Toda funcion recibe tipos simples (str, int, dict) y retorna
tipos simples - nunca objetos sqlite3.Row fuera de este archivo.
"""

import json
import logging
from datetime import datetime

from db.database import get_connection

logger = logging.getLogger('AgenteSDN.repository')


# ===============================================================================
# ESTADO DE LA RED
# ===============================================================================

def get_estado_red() -> dict:
    with get_connection() as conn:
        rows = conn.execute('SELECT clave, valor FROM estado_red').fetchall()
    return {r['clave']: r['valor'] for r in rows}


def set_estado_red(clave: str, valor: str) -> None:
    with get_connection() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO estado_red (clave, valor) VALUES (?,?)',
            (clave, str(valor))
        )


def incrementar_incidentes_sesion() -> int:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT valor FROM estado_red WHERE clave='incidentes_sesion'"
        ).fetchone()
        count = int(row['valor']) + 1 if row else 1
        conn.execute(
            "INSERT OR REPLACE INTO estado_red VALUES ('incidentes_sesion',?)",
            (str(count),)
        )
    return count


# ===============================================================================
# INCIDENTES
# ===============================================================================

def registrar_incidente(payload: dict, veredicto: dict) -> None:
    """Guarda el incidente completo y actualiza el estado de la red."""
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO incidentes
                (host, timestamp, puntaje, metricas, veredicto, confianza, nivel_auto, payload)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            payload['host_origen'],
            payload['timestamp'],
            payload.get('puntaje_total', 0),
            json.dumps(payload.get('umbrales_superados', [])),
            veredicto.get('veredicto', 'indeterminado'),
            veredicto.get('confianza', 0),
            veredicto.get('nivel_autonomia', 1),
            json.dumps(payload),
        ))

        # Registrar host como bloqueado
        conn.execute("""
            INSERT OR REPLACE INTO hosts_bloqueados
                (ip, timestamp, puntaje, veredicto, confianza, dpid)
            VALUES (?,?,?,?,?,?)
        """, (
            payload['host_origen'],
            payload['timestamp'],
            payload.get('puntaje_total', 0),
            veredicto.get('veredicto', 'indeterminado'),
            veredicto.get('confianza', 0),
            payload.get('dpid_switch', 'unknown'),
        ))

        # Registrar hosts en riesgo
        for host in veredicto.get('hosts_en_riesgo', []):
            conn.execute("""
                INSERT OR REPLACE INTO hosts_riesgo
                    (ip, razon, timestamp, origen_ip)
                VALUES (?,?,?,?)
            """, (
                host,
                f'contactado por {payload["host_origen"]} via SMB',
                payload['timestamp'],
                payload['host_origen'],
            ))

        # Actualizar nivel de alerta
        nivel = veredicto.get('actualizar_estado_red', {}).get('nivel_alerta_red', 'ALTO')
        conn.execute(
            "INSERT OR REPLACE INTO estado_red VALUES ('nivel_alerta',?)",
            (nivel,)
        )

        # Incrementar contador de sesion
        row = conn.execute(
            "SELECT valor FROM estado_red WHERE clave='incidentes_sesion'"
        ).fetchone()
        count = int(row['valor']) + 1 if row else 1
        conn.execute(
            "INSERT OR REPLACE INTO estado_red VALUES ('incidentes_sesion',?)",
            (str(count),)
        )

    logger.info(f'[Repository] Incidente registrado: {payload["host_origen"]} '
                f'-> {veredicto.get("veredicto")}')


def get_incidentes(limite: int = 50) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT host, timestamp, puntaje, veredicto, confianza, nivel_auto, metricas
            FROM incidentes
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limite,)).fetchall()
    return [{
        'host':      r['host'],
        'timestamp': r['timestamp'],
        'puntaje':   r['puntaje'],
        'veredicto': r['veredicto'],
        'confianza': r['confianza'],
        'nivel':     r['nivel_auto'],
        'metricas':  json.loads(r['metricas'] or '[]'),
    } for r in rows]


def get_historial_host(ip: str, limite: int = 10) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT timestamp, puntaje, veredicto, confianza, metricas
            FROM incidentes
            WHERE host = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (ip, limite)).fetchall()
    return [{
        'timestamp': r['timestamp'],
        'puntaje':   r['puntaje'],
        'veredicto': r['veredicto'],
        'confianza': r['confianza'],
        'metricas':  json.loads(r['metricas'] or '[]'),
    } for r in rows]


# ===============================================================================
# HOSTS BLOQUEADOS
# ===============================================================================

def get_hosts_bloqueados() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute('SELECT * FROM hosts_bloqueados').fetchall()
    return [{
        'ip':        r['ip'],
        'timestamp': r['timestamp'],
        'puntaje':   r['puntaje'],
        'veredicto': r['veredicto'],
        'confianza': r['confianza'],
        'dpid':      r['dpid'],
    } for r in rows]


def desbloquear_host_db(ip: str) -> None:
    with get_connection() as conn:
        conn.execute('DELETE FROM hosts_bloqueados WHERE ip=?', (ip,))
        conn.execute('DELETE FROM hosts_riesgo WHERE ip=?', (ip,))
    logger.info(f'[Repository] Host desbloqueado en DB: {ip}')


# ===============================================================================
# HOSTS EN RIESGO
# ===============================================================================

def get_hosts_riesgo() -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute('SELECT * FROM hosts_riesgo').fetchall()
    return [{
        'ip':        r['ip'],
        'razon':     r['razon'],
        'timestamp': r['timestamp'],
        'origen':    r['origen_ip'],
    } for r in rows]


# ===============================================================================
# WHITELIST
# ===============================================================================

def agregar_whitelist(ip: str, razon: str = '') -> None:
    with get_connection() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO whitelist (ip, agregado, razon) VALUES (?,?,?)',
            (ip, datetime.utcnow().isoformat(), razon)
        )
    logger.info(f'[Repository] IP agregada a whitelist: {ip}')


def esta_en_whitelist(ip: str) -> bool:
    with get_connection() as conn:
        row = conn.execute(
            'SELECT ip FROM whitelist WHERE ip=?', (ip,)
        ).fetchone()
    return row is not None


# ===============================================================================
# UMBRALES
# ===============================================================================

def get_umbrales() -> dict:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT clave, valor FROM estado_red WHERE clave LIKE 'umbral_%'"
        ).fetchall()
    return {r['clave'].replace('umbral_', ''): int(r['valor']) for r in rows}


def set_umbral(nombre: str, valor: int) -> None:
    with get_connection() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO estado_red (clave, valor) VALUES (?,?)',
            (f'umbral_{nombre}', str(valor))
        )