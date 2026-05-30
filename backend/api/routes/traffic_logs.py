import os
from fastapi import APIRouter, Query
from typing import Optional, List
from backend.api.schemas.models import TrafficLogsResponse, TrafficLogEntry

router = APIRouter()

TRAFFIC_LOG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "phase1", "logs", "traffic.log")
)

@router.get("/traffic-logs", response_model=TrafficLogsResponse)
def read_traffic_logs(
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100)
):
    """Parses and returns live packet traffic logging from Scapy engine."""
    logs = []
    if not os.path.exists(TRAFFIC_LOG_PATH):
        return {"total": 0, "logs": []}

    with open(TRAFFIC_LOG_PATH, "r") as f:
        lines = f.readlines()

    idx = 1
    for line in reversed(lines):
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        
        timestamp = parts[0]
        
        ips = [i.strip() for i in parts[1].split("->")]
        if len(ips) < 2:
            continue
        source_ip, destination_ip = ips[0], ips[1]
        
        protocol = parts[2]
        
        ports = [p.strip() for p in parts[3].split("->")]
        if len(ports) < 2:
            continue
        try:
            source_port, destination_port = int(ports[0]), int(ports[1])
        except ValueError:
            source_port, destination_port = 0, 0
            
        size_str = parts[4].replace("bytes", "").strip()
        try:
            packet_size = int(size_str)
        except ValueError:
            packet_size = 0

        # Filtering
        if search:
            s_lower = search.lower()
            match = (
                s_lower in timestamp.lower() or
                s_lower in source_ip.lower() or
                s_lower in destination_ip.lower() or
                s_lower in protocol.lower() or
                s_lower in str(source_port) or
                s_lower in str(destination_port)
            )
            if not match:
                continue

        logs.append(
            TrafficLogEntry(
                id=idx,
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                source_port=source_port,
                destination_port=destination_port,
                packet_size=packet_size
            )
        )
        idx += 1

    total = len(logs)
    start = (page - 1) * limit
    end = start + limit
    paginated_logs = logs[start:end]

    return {"total": total, "logs": paginated_logs}
