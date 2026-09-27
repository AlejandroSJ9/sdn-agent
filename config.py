"""
config.py
Unica fuente de verdad para toda la configuracion del agente.
Configurado para OpenRouter -- proxy compatible con OpenAI
que permite elegir entre multiples modelos (incluidos gratuitos).

Obtener API key en: https://openrouter.ai/keys
"""

import os
from dotenv import load_dotenv

load_dotenv()

# -- OpenRouter ---------------------------------------------------------------
# OpenRouter usa el mismo formato de request/response que OpenAI.
# Solo cambia la URL base y el nombre de la API key.
#
# Modelos gratuitos recomendados:
#   meta-llama/llama-3.1-8b-instruct:free  (recomendado -- 128k contexto)
#   meta-llama/llama-3.2-3b-instruct:free  (mas rapido, menos preciso)
#   google/gemma-2-9b-it:free              (buena alternativa)
#   mistralai/mistral-7b-instruct:free     (32k contexto)
#   qwen/qwen-2.5-7b-instruct:free         (32k contexto)
#
# Para cambiar de modelo: editar OPENAI_MODEL en .env

OPENAI_API_KEY    = os.getenv('OPENROUTER_API_KEY', os.getenv('OPENAI_API_KEY', ''))
OPENAI_MODEL      = os.getenv('OPENAI_MODEL', os.getenv('OPENAI_MODEL', 'meta-llama/llama-3.1-8b-instruct:free'))
OPENAI_TEMP       = float(os.getenv('OPENAI_TEMP', '0.1'))
OPENAI_MAX_TOKENS = int(os.getenv('OPENAI_MAX_TOKENS', '2000'))
OPENAI_TIMEOUT    = int(os.getenv('OPENAI_TIMEOUT', '30'))

# URL de OpenRouter -- compatible con el formato de OpenAI
OPENAI_URL = 'https://openrouter.ai/api/v1/chat/completions'

# Headers adicionales recomendados por OpenRouter para identificar la app
# Aparecen en el dashboard de OpenRouter para monitorear el uso
OPENROUTER_SITE_URL = os.getenv('OPENROUTER_SITE_URL', 'http://localhost:8081')
OPENROUTER_APP_NAME = os.getenv('OPENROUTER_APP_NAME', 'SDN-Agent')

if not OPENAI_API_KEY:
    raise EnvironmentError(
        'OPENROUTER_API_KEY no esta configurada.\n'
        'Obtenerla en: https://openrouter.ai/keys\n'
        'Agregarla en .env como: OPENROUTER_API_KEY=sk-or-...'
    )

# -- Telegram -----------------------------------------------------------------
TELEGRAM_TOKEN    = os.getenv('TELEGRAM_TOKEN',   '')
TELEGRAM_CHAT_ID  = os.getenv('TELEGRAM_CHAT_ID', '')
TELEGRAM_ENABLED  = os.getenv('TELEGRAM_ENABLED', 'true').lower() == 'true'
TELEGRAM_POLL_SEC = int(os.getenv('TELEGRAM_POLL_SEC', '2'))

if TELEGRAM_ENABLED and (not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID):
    raise EnvironmentError(
        'TELEGRAM_TOKEN y TELEGRAM_CHAT_ID son obligatorios cuando '
        'TELEGRAM_ENABLED=true.\n'
        'Configurarlos en .env o poner TELEGRAM_ENABLED=false.'
    )

# -- Ryu REST -----------------------------------------------------------------
RYU_REST_URL = os.getenv('RYU_REST_URL', 'http://localhost:8080')
RYU_TIMEOUT  = int(os.getenv('RYU_TIMEOUT', '5'))

# -- Logica del agente --------------------------------------------------------
MAX_TURNOS_LLM        = int(os.getenv('MAX_TURNOS_LLM', '3'))
HITL_TIMEOUT_SEGUNDOS = int(os.getenv('HITL_TIMEOUT_SEC', '600'))

# -- Base de datos ------------------------------------------------------------
DB_FILE = os.getenv('DB_FILE', 'sdn_context.db')

# -- Umbrales -----------------------------------------------------------------
SCORE_SUSPICIOUS = int(os.getenv('SCORE_SUSPICIOUS', '30'))
SCORE_CRITICAL   = int(os.getenv('SCORE_CRITICAL',   '60'))

METRIC_WEIGHTS: dict = {
    'M5': 40,
    'M3': 35,
    'M1': 25,
    'M2': 20,
    'M4': 15,
}

# -- Topologia ----------------------------------------------------------------
SUBNET_OPS = '10.0.10.'
SUBNET_ADM = '10.0.20.'
VLAN_OPS   = 10
VLAN_ADM   = 20