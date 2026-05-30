from fastapi import APIRouter
from backend.api.schemas.models import GeoResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/geo", response_model=GeoResponse)
def read_geo_intelligence():
    """Get internal vs external connection ratios and ranking list of active external hosts."""
    return engine_bridge.get_geo_intelligence()
