# SDN-Agent -- Agente LLM para Respuesta a Ransomware

**Universidad Catolica de Colombia -- Facultad de Ingenieria -- 2026**
Alejandro Salas Jurado - Sebastian Briceno Restrepo

Agente autonomo que recibe alertas del controlador SDN
([Ryu-IA](https://github.com/sbriceno1379/Ryu-IA)),
las analiza con GPT-4o-mini de forma bidireccional, notifica al operador
via Telegram con botones HITL, y ejecuta acciones en la red via REST API de Ryu.

---

## Proyectos relacionados

| Proyecto | Repositorio | Funcion |
|---|---|---|
| **Ryu-IA** | `sbriceno1379/Ryu-IA` | Controlador SDN + deteccion |
| **SDN-Agent** (este) | `AlejandroSJ9/sdn-agent` | Agente LLM + alertas + HITL |

> **Orden de arranque:** primero Ryu-IA, luego SDN-Agent.

---

## Requisitos del sistema

- Ubuntu 20.04 / 22.04 | Debian
- Python 3.8+
- El proyecto **Ryu-IA** corriendo en el mismo host o accesible por red

---

## Instalacion

```bash
git clone https://github.com/sbriceno1379/sdn-agent.git
cd sdn-agent

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
nano .env    # rellenar OPENAI_API_KEY, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
```

---

## Uso

```bash
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8081 --reload
```

El agente estara disponible en:
- **API REST:** `http://localhost:8081`
- **Documentacion:** `http://localhost:8081/docs`
- **WebSocket:** `ws://localhost:8081/ws/eventos`

---

## Estructura

```
sdn-agent/
|-- main.py                  # Punto de entrada FastAPI
|-- config.py                # Configuracion centralizada (.env)
|-- requirements.txt
|-- .env.example
|-- .gitignore
|-- README.md
|
|-- api/                     # Capa HTTP
|   |-- routes_alertas.py    # POST /alert  <- recibe de Ryu-IA
|   |-- routes_dashboard.py  # GET  /estado /incidentes /hosts
|   |-- routes_acciones.py   # POST /accion /umbrales
|   \-- websocket.py         # WS   /ws/eventos
|
|-- services/                # Logica de negocio
|   |-- agente.py            # Orquestador del flujo completo
|   |-- llm.py               # Loop bidireccional con OpenAI
|   \-- prompt.py            # Construccion de prompts
|
|-- integrations/            # Sistemas externos
|   |-- ryu_rest.py          # Cliente REST API de Ryu-IA
|   \-- telegram.py          # Bot de Telegram + polling HITL
|
\-- db/                      # Persistencia
    |-- database.py          # Context manager SQLite
    |-- models.py            # Esquema de tablas
    \-- repository.py        # Queries (unico archivo con SQL)
```

---

## Endpoints principales

| Metodo | Endpoint | Descripcion |
|---|---|---|
| POST | `/alert` | Recibe alerta critica de Ryu-IA |
| GET | `/estado` | Estado actual de la red |
| GET | `/incidentes` | Historial de incidentes |
| GET | `/hosts` | Hosts bloqueados y en riesgo |
| POST | `/accion` | Accion manual del operador |
| POST | `/umbrales` | Actualizar umbrales de deteccion |
| GET | `/health` | Estado del agente |
| WS | `/ws/eventos` | Eventos en tiempo real al dashboard |

---

## Flujo de un incidente

```
Ryu-IA detecta puntaje >= 60 y bloquea el equipo (DROP)
    | POST /alert (JSON)
    v
SDN-Agent
    |-- 1. Arma un resumen: metricas + lista blanca + alertas anteriores
    |-- 2. Una sola llamada al LLM -> {"veredicto", "explicacion"}
    |      (respuesta invalida: un reintento; si falla -> indeterminado)
    |-- 3. falso_positivo sin lista blanca ni historial -> indeterminado
    |-- 4. Responde a Ryu: siempre mantener_bloqueo
    \-- 5. Telegram notifica (solo informativo) y se guarda en la DB
```

El agente nunca desbloquea un equipo por su cuenta: el operador lo hace a mano
con `POST /accion` (requiere el encabezado `X-API-Key`).

---

## Como obtener las credenciales

### OpenAI API Key
1. Ir a [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Crear una nueva clave
3. Pegar en `.env` como `OPENAI_API_KEY`

### Telegram Bot
1. Abrir Telegram -> buscar `@BotFather`
2. Escribir `/newbot` y seguir las instrucciones
3. Copiar el token -> `TELEGRAM_TOKEN` en `.env`
4. Mandar un mensaje al bot
5. Abrir `https://api.telegram.org/bot<TOKEN>/getUpdates`
6. Copiar el numero de `"chat":{"id": XXXXX}` -> `TELEGRAM_CHAT_ID`

---

## Variables de entorno

| Variable | Descripcion | Obligatoria |
|---|---|---|
| `OPENAI_API_KEY` | Clave API de OpenAI | Si |
| `TELEGRAM_TOKEN` | Token del bot de Telegram | Si (si TELEGRAM_ENABLED=true) |
| `TELEGRAM_CHAT_ID` | ID del chat del operador | Si (si TELEGRAM_ENABLED=true) |
| `RYU_REST_URL` | URL REST API de Ryu-IA | No (default: localhost:8080) |
| `TELEGRAM_ENABLED` | Activar Telegram | No (default: true) |
| `DB_FILE` | Ruta de la base de datos SQLite | No (default: sdn_context.db) |
| `AGENTE_API_KEY` | Clave para `POST /accion` y `/umbrales` (encabezado `X-API-Key`) | Si, para usar esos endpoints |

---

## Seguridad

- Las credenciales viven solo en `.env` -- nunca en el codigo
- `.env` esta en `.gitignore` -- nunca se sube a GitHub
- El agente nunca desbloquea hosts automaticamente; `POST /accion` exige `X-API-Key`
- Veredicto fallback conservador si OpenAI falla (mantener bloqueo)

---

## Licencia

Proyecto academico -- Universidad Catolica de Colombia 2026.