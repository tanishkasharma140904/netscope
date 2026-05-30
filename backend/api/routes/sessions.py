from fastapi import APIRouter
from backend.api.schemas.models import SessionsResponse, SessionAnalyticsResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/sessions", response_model=SessionsResponse)
def read_sessions():
    """Get active sessions tracked in real time, including packets, bytes, and duration."""
    return engine_bridge.get_sessions()

@router.get("/session-analytics", response_model=SessionAnalyticsResponse)
def read_session_analytics():
    """Get calculated longest, largest, most active session telemetry from live memory."""
    return engine_bridge.get_session_analytics()
