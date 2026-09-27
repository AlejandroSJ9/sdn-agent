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
from db.models import SCHEMA

logger = logging.getLogger('AgenteSDN.db')


def init_db() -> None:
    """Crea las tablas si no existen. Llamar una sola vez al arrancar."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    logger.info(f'[DB] Base de datos inicializada: {DB_FILE}')


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