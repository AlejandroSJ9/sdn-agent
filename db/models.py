"""
db/models.py
Definicion del esquema de la base de datos como constantes SQL.
Separado de la logica de queries para poder cambiar el motor de DB
sin tocar el resto del codigo.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidentes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    puntaje     INTEGER,
    metricas    TEXT,
    veredicto   TEXT,
    confianza   INTEGER,
    nivel_auto  INTEGER,
    payload     TEXT
);

CREATE TABLE IF NOT EXISTS hosts_bloqueados (
    ip        TEXT PRIMARY KEY,
    timestamp TEXT    NOT NULL,
    puntaje   INTEGER,
    veredicto TEXT,
    confianza INTEGER,
    dpid      TEXT
);

CREATE TABLE IF NOT EXISTS hosts_riesgo (
    ip        TEXT PRIMARY KEY,
    razon     TEXT,
    timestamp TEXT NOT NULL,
    origen_ip TEXT
);

CREATE TABLE IF NOT EXISTS whitelist (
    ip      TEXT PRIMARY KEY,
    agregado TEXT NOT NULL,
    razon    TEXT
);

CREATE TABLE IF NOT EXISTS estado_red (
    clave TEXT PRIMARY KEY,
    valor TEXT
);

INSERT OR IGNORE INTO estado_red VALUES ('nivel_alerta','NORMAL');
INSERT OR IGNORE INTO estado_red VALUES ('incidentes_sesion', '0');
"""