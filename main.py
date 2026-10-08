"""
main.py
Punto de entrada del agente SDN.
Solo responsabilidad: crear la app FastAPI, registrar routers
y gestionar el ciclo de vida (startup/shutdown).
Ninguna logica de negocio vive aqui.

Uso:
    uvicorn main:app --host 0.0.0.0 --port 8081 --reload

Variables de entorno:
    OPENAI_API_KEY      -> clave de OpenAI (obligatoria)
    TELEGRAM_TOKEN      -> token del bot de Telegram
    TELEGRAM_CHAT_ID    -> chat_id del operador
    TELEGRAM_ENABLED    -> true/false (default: true)
    RYU_REST_URL        -> URL de la REST API de Ryu (default: http://localhost:8080)
    DB_FILE             -> ruta del archivo SQLite (default: sdn_context.db)
    AGENTE_API_KEY      -> clave para POST /accion y /umbrales (encabezado X-API-Key)
"""

import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from config import OPENAI_MODEL, RYU_REST_URL, TELEGRAM_ENABLED
from services.agente import iniciar_servicios
from api.routes_alertas   import router as router_alertas
from api.routes_dashboard import router as router_dashboard
from api.routes_acciones  import router as router_acciones
from api.websocket        import ws_endpoint

logger = logging.getLogger('AgenteSDN')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)

# --- App ----------------------------------------------------------------------

app = FastAPI(
    title='SDN Security Agent',
    description=(
        'Agente autonomo para deteccion y respuesta a ransomware en redes SDN. '
        'Recibe alertas del controlador Ryu, las analiza con un LLM y notifica por Telegram.'
    ),
    version='2.0.0',
    docs_url='/docs',
    redoc_url='/redoc',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

# --- Routers ------------------------------------------------------------------

app.include_router(router_alertas)
app.include_router(router_dashboard)
app.include_router(router_acciones)
app.add_api_websocket_route('/ws/eventos', ws_endpoint)

# --- Lifecycle ----------------------------------------------------------------

@app.on_event('startup')
async def startup():
    iniciar_servicios()
    logger.info('=' * 60)
    logger.info('  SDN Security Agent v2.0 iniciado')
    logger.info(f'  Modelo LLM:  {OPENAI_MODEL}')
    logger.info(f'  Ryu REST:    {RYU_REST_URL}')
    logger.info(f'  Telegram:    {"activo" if TELEGRAM_ENABLED else "desactivado"}')
    logger.info('  Docs:        http://localhost:8081/docs')
    logger.info('=' * 60)


@app.on_event('shutdown')
async def shutdown():
    logger.info('[App] Agente detenido correctamente.')


# --- Health check -------------------------------------------------------------

@app.get('/health', tags=['Sistema'], summary='Estado del agente')
def health():
    from datetime import datetime
    from api.websocket import ws_manager
    return {
        'status':            'ok',
        'modelo':            OPENAI_MODEL,
        'ryu_rest':          RYU_REST_URL,
        'telegram':          TELEGRAM_ENABLED,
        'ws_clientes':       ws_manager.num_clientes,
        'ts':                datetime.utcnow().isoformat() + 'Z',
    }


# --- Demo -------------------------------------------------------------------

@app.get('/demo', include_in_schema=False)
def demo():
    """Interfaz web que muestra en vivo la interaccion Ryu <-> agente."""
    return FileResponse(Path(__file__).parent / 'frontend' / 'demo.html')


# --- Entry point --------------------------------------------------------------

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        'main:app',
        host='0.0.0.0',
        port=8081,
        reload=False,
        log_level='info',
    )