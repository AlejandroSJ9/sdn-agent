"""
api/websocket.py
Gestion de conexiones WebSocket para streaming de eventos al frontend.
El WSManager es un singleton que vive aqui y es importado por las rutas.
"""

import json
import logging
from fastapi import WebSocket, WebSocketDisconnect

from db.repository import get_estado_red, get_hosts_bloqueados

logger = logging.getLogger('AgenteSDN.ws')


class WSManager:
    """
    Gestor de conexiones WebSocket activas.
    Permite hacer broadcast a todos los clientes conectados.
    """

    def __init__(self):
        self._clientes: list[WebSocket] = []

    async def conectar(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clientes.append(ws)
        logger.info(f'[WS] Cliente conectado - total: {len(self._clientes)}')

    def desconectar(self, ws: WebSocket) -> None:
        if ws in self._clientes:
            self._clientes.remove(ws)
        logger.info(f'[WS] Cliente desconectado - total: {len(self._clientes)}')

    async def broadcast(self, data: dict) -> None:
        """Envia un evento JSON a todos los clientes conectados."""
        texto   = json.dumps(data, ensure_ascii=False)
        muertos = []
        for ws in list(self._clientes):
            try:
                await ws.send_text(texto)
            except Exception:
                muertos.append(ws)
        for ws in muertos:
            self.desconectar(ws)

    def emit_sync(self, data: dict) -> None:
        """
        Version sincrona de broadcast para usar desde hilos no-async
        (como los callbacks de Telegram).
        Requiere que el event loop este corriendo.
        """
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(data), loop)
        except RuntimeError:
            logger.debug('[WS] emit_sync: no hay event loop activo')

    @property
    def num_clientes(self) -> int:
        return len(self._clientes)


# Singleton - importar desde aqui en todas las rutas
ws_manager = WSManager()


async def ws_endpoint(ws: WebSocket) -> None:
    """
    Handler del endpoint WebSocket /ws/eventos.
    Envia el estado inicial al conectarse y mantiene la conexion viva.
    """
    await ws_manager.conectar(ws)
    try:
        # Estado inicial al conectarse
        await ws.send_text(json.dumps({
            'tipo':   'estado_inicial',
            'estado': get_estado_red(),
            'hosts':  get_hosts_bloqueados(),
        }, ensure_ascii=False))

        # Mantener la conexion viva esperando mensajes del cliente
        while True:
            await ws.receive_text()

    except WebSocketDisconnect:
        ws_manager.desconectar(ws)
    except Exception as e:
        logger.error(f'[WS] Error en conexion: {e}')
        ws_manager.desconectar(ws)