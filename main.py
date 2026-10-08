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
    LLM_PIPELINE        -> etapas | monolitico (default: etapas)
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import OPENAI_MODEL, RYU_REST_URL, TELEGRAM_ENABLED, LLM_PIPELINE
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
        'Orquesta entre el controlador Ryu, OpenAI GPT-4o-mini y Telegram HITL.'
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
    logger.info(f'  Pipeline:    {LLM_PIPELINE}')
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
    from integrations.telegram import get_acciones_pendientes
    return {
        'status':            'ok',
        'modelo':            OPENAI_MODEL,
        'pipeline':          LLM_PIPELINE,
        'ryu_rest':          RYU_REST_URL,
        'telegram':          TELEGRAM_ENABLED,
        'ws_clientes':       ws_manager.num_clientes,
        'hitl_pendientes':   len(get_acciones_pendientes()),
        'ts':                datetime.utcnow().isoformat() + 'Z',
    }


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