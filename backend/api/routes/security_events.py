import os
from fastapi import APIRouter
from typing import Optional, List
from backend.api.schemas.models import SecurityEventsResponse, SecurityEventEntry

router = APIRouter()

ALERTS_LOG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "phase1", "logs", "alerts.log")
)

@router.get("/security-events", response_model=SecurityEventsResponse)
def read_security_events(search: Optional[str] = None):
    """Parses and returns live security alert events from logging directory."""
    events = []
    if not os.path.exists(ALERTS_LOG_PATH):
        return {"total": 0, "events": []}

    with open(ALERTS_LOG_PATH, "r") as f:
        lines = f.readlines()

    idx = 1
    for line in reversed(lines):
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|", 1)]
        if len(parts) < 2:
            continue
            
        timestamp = parts[0]
        message = parts[1]
        
        # Classify event type
        alert_type = "Anomaly"
        msg_lower = message.lower()
        if "port scan" in msg_lower:
            alert_type = "Port Scan"
        elif "reconnaissance" in msg_lower or "icmp" in msg_lower:
            alert_type = "Reconnaissance"
        elif "suspicious port" in msg_lower:
            alert_type = "Suspicious Port"
        elif "bandwidth" in msg_lower:
            alert_type = "Bandwidth Spike"
        elif "udp" in msg_lower:
            alert_type = "Protocol Abuse"
        elif "dominance" in msg_lower:
            alert_type = "Network Dominance"

        # Filtering
        if search:
            s_lower = search.lower()
            match = (
                s_lower in timestamp.lower() or
                s_lower in alert_type.lower() or
                s_lower in message.lower()
            )
            if not match:
                continue

        events.append(
            SecurityEventEntry(
                id=idx,
                timestamp=timestamp,
                classification=alert_type,
                message=message
            )
        )
        idx += 1

    return {"total": len(events), "events": events}
