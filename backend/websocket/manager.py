# =============================================================
#   NetScope AI — WebSocket Connection Managers
#   Manages active WebSocket endpoints with auto-cleanup
# =============================================================

from fastapi import WebSocket
from typing import List

class ConnectionManager:
    """Manages tracking, connectivity, and broadcasting to active WebSocket sessions."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accepts and records a new client connection."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Removes a client connection from active tracking."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Sends a JSON payload to all active clients and prunes dead links."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        # Automatically clean up disconnected/broken links
        for dead in dead_connections:
            self.disconnect(dead)


# Isolated managers for each individual real-time telemetry stream
stats_manager = ConnectionManager()
threats_manager = ConnectionManager()
sessions_manager = ConnectionManager()
hosts_manager = ConnectionManager()
