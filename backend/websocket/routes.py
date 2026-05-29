# =============================================================
#   NetScope AI — WebSocket Router Endpoints
#   Declares WebSocket streaming routes for real-time telemetry
# =============================================================

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.websocket.manager import (
    stats_manager,
    threats_manager,
    sessions_manager,
    hosts_manager
)

router = APIRouter(tags=["WebSocket Streaming"])

@router.websocket("/ws/live/stats")
async def ws_stats(websocket: WebSocket):
    """Real-time protocol statistics and packet volume stream."""
    print("[WS] Stats client connecting...")
    try:
        await stats_manager.connect(websocket)
        print("[WS] Stats client connected successfully")
        while True:
            # Keeps connection alive and listens for heartbeat or disconnections
            await websocket.receive_text()
    except WebSocketDisconnect:
        print("[WS] Stats client disconnected")
        stats_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS ERROR] Stats connection error: {e}")
        stats_manager.disconnect(websocket)


@router.websocket("/ws/live/threats")
async def ws_threats(websocket: WebSocket):
    """Real-time active threats, score, and risk level stream."""
    print("[WS] Threats client connecting...")
    try:
        await threats_manager.connect(websocket)
        print("[WS] Threats client connected successfully")
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        print("[WS] Threats client disconnected")
        threats_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS ERROR] Threats connection error: {e}")
        threats_manager.disconnect(websocket)


@router.websocket("/ws/live/sessions")
async def ws_sessions(websocket: WebSocket):
    """Real-time top active sessions logs stream."""
    print("[WS] Sessions client connecting...")
    try:
        await sessions_manager.connect(websocket)
        print("[WS] Sessions client connected successfully")
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        print("[WS] Sessions client disconnected")
        sessions_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS ERROR] Sessions connection error: {e}")
        sessions_manager.disconnect(websocket)


@router.websocket("/ws/live/hosts")
async def ws_hosts(websocket: WebSocket):
    """Real-time newly discovered hosts inventory stream."""
    print("[WS] Hosts client connecting...")
    try:
        await hosts_manager.connect(websocket)
        print("[WS] Hosts client connected successfully")
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        print("[WS] Hosts client disconnected")
        hosts_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS ERROR] Hosts connection error: {e}")
        hosts_manager.disconnect(websocket)
