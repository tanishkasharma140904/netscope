from fastapi import APIRouter
from backend.api.schemas.models import ThreatResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/threats", response_model=ThreatResponse)
def read_threats():
    """Get security logs, threat score, risk level, and currently triggered security anomalies."""
    return engine_bridge.get_threats()
