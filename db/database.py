"""
db/database.py
Gestion de la conexion a SQLite.
Provee un context manager para garantizar que cada operacion
abre y cierra la conexion correctamente, sin dejar handles abiertos.
"""

import sqlite3
import logging
from contextlib import contextmanager

from config import DB_FILE
from db.models import SCHEMA, COLUMNAS_NUEVAS

logger = logging.getLogger('AgenteSDN.db')


def init_db() -> None:
    """Crea las tablas si no existen. Llamar una sola vez al arrancar."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        _migrar_columnas(conn)
    logger.info(f'[DB] Base de datos inicializada: {DB_FILE}')


def _migrar_columnas(conn: sqlite3.Connection) -> None:
    """Agrega a las tablas existentes las columnas de COLUMNAS_NUEVAS que falten."""
    for tabla, columnas in COLUMNAS_NUEVAS.items():
        existentes = {r['name'] for r in conn.execute(f'PRAGMA table_info({tabla})')}
        for nombre, tipo in columnas.items():
            if nombre not in existentes:
                conn.execute(f'ALTER TABLE {tabla} ADD COLUMN {nombre} {tipo}')
                logger.info(f'[DB] Migracion: columna {tabla}.{nombre} agregada')


@contextmanager
def get_connection():
    """
    Context manager que garantiza apertura, commit y cierre de la conexion.

    Uso:
        with get_connection() as conn:
            conn.execute(...)

    Si ocurre una excepcion dentro del bloque, hace rollback automatico.
    Si todo va bien, hace commit al salir del bloque.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row   # permite acceder a columnas por nombre
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()