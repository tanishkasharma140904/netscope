from fastapi import APIRouter
from backend.api.schemas.models import PortsResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/ports", response_model=PortsResponse)
def read_top_ports():
    """Get the top 10 most active destination ports and their common service names."""
    return engine_bridge.get_top_ports()
