from fastapi import APIRouter
from backend.api.schemas.models import InventoryResponse
from backend.api.services import engine_bridge

router = APIRouter()

@router.get("/inventory", response_model=InventoryResponse)
def read_inventory():
    """Get network host inventory tracking first seen, last seen, and packet volume per host."""
    return engine_bridge.get_inventory()
