from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database.database import get_db
from backend.database import models
from backend.api.schemas.models import AlertHistoryResponseEntry

router = APIRouter()

@router.get("/alert-history", response_model=List[AlertHistoryResponseEntry])
def read_alert_history(
    search: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve full triggered alert log records with advanced search and filters."""
    query = db.query(models.AlertRecord).order_by(models.AlertRecord.id.desc())
    
    if category:
        query = query.filter(models.AlertRecord.alert_type == category)
    if severity:
        query = query.filter(models.AlertRecord.severity == severity)
    if search:
        query = query.filter(models.AlertRecord.message.icontains(search))
        
    alerts = query.limit(100).all()
    
    return [
        AlertHistoryResponseEntry(
            id=alert.id,
            alert_type=alert.alert_type,
            severity=alert.severity,
            message=alert.message,
            timestamp=alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        )
        for alert in alerts
    ]
