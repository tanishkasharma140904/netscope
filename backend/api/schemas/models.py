# =============================================================
#   NetScope AI — API Response Schemas
#   Pydantic models for all REST endpoints
# =============================================================

from pydantic import BaseModel
from typing import List, Optional


# =============================================================
#   /api/stats
# =============================================================

class StatsResponse(BaseModel):

    total_packets: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    total_data: str


# =============================================================
#   /api/top-talkers
# =============================================================

class TopTalkerEntry(BaseModel):

    rank: int
    ip: str
    packet_count: int


class TopTalkersResponse(BaseModel):

    top_talkers: List[TopTalkerEntry]


# =============================================================
#   /api/ports
# =============================================================

class PortEntry(BaseModel):

    rank: int
    port: int
    service: str
    packet_count: int


class PortsResponse(BaseModel):

    top_ports: List[PortEntry]


# =============================================================
#   /api/sessions
# =============================================================

class SessionEntry(BaseModel):

    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packets: int
    bytes: int
    duration: float


class SessionsResponse(BaseModel):

    session_count: int
    active_sessions: List[SessionEntry]


# =============================================================
#   /api/threats
# =============================================================

class ThreatResponse(BaseModel):

    threat_score: int
    risk_level: str
    active_threats: List[str]
    recent_alerts: List[str]


# =============================================================
#   /api/inventory
# =============================================================

class InventoryEntry(BaseModel):

    ip: str
    first_seen: str
    last_seen: str
    packet_count: int


class InventoryResponse(BaseModel):

    host_count: int
    hosts: List[InventoryEntry]


# =============================================================
#   /api/applications
# =============================================================

class ApplicationEntry(BaseModel):

    name: str
    packet_count: int
    percentage: float


class ApplicationsResponse(BaseModel):

    applications: List[ApplicationEntry]


# =============================================================
#   /api/executive-summary
# =============================================================

class ExecutiveSummaryResponse(BaseModel):

    threat_score: int
    risk_level: str
    security_health: int
    total_hosts: int
    total_sessions: int
    total_alerts: int
    top_threat: Optional[str]
    top_application: Optional[str]


# =============================================================
#   NetScope AI — Historical Response Schemas (Stage 2)
# =============================================================

from datetime import datetime

class HostHistoryEntry(BaseModel):
    id: int
    ip_address: str
    first_seen: str
    last_seen: str
    packet_count: int
    is_internal: bool

    class Config:
        from_attributes = True


class SessionHistoryEntry(BaseModel):
    id: int
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packets: int
    bytes: int
    duration: float
    timestamp: datetime

    class Config:
        from_attributes = True


class AlertHistoryEntry(BaseModel):
    id: int
    alert_type: str
    severity: str
    message: str
    timestamp: datetime

    class Config:
        from_attributes = True


class ThreatHistoryEntry(BaseModel):
    id: int
    threat_name: str
    category: str
    risk_level: str
    score: int
    timestamp: datetime

    class Config:
        from_attributes = True


class StatsHistoryEntry(BaseModel):
    id: int
    total_packets: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    total_data: str
    timestamp: datetime

    class Config:
        from_attributes = True


class GeoHostEntry(BaseModel):
    ip: str
    packet_count: int

class GeoResponse(BaseModel):
    internal_connections: int
    external_connections: int
    internal_ratio: float
    external_ratio: float
    top_external_hosts: List[GeoHostEntry]

class SessionAnalyticsEntry(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packets: int
    bytes: int
    duration: float

class SessionAnalyticsResponse(BaseModel):
    active_sessions_count: int
    expired_sessions_count: int
    longest_session: Optional[SessionAnalyticsEntry]
    largest_session: Optional[SessionAnalyticsEntry]
    most_active_session: Optional[SessionAnalyticsEntry]

class AlertHistoryResponseEntry(BaseModel):
    id: int
    alert_type: str
    severity: str
    message: str
    timestamp: str

class TrafficLogEntry(BaseModel):
    id: int
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    packet_size: int

class TrafficLogsResponse(BaseModel):
    total: int
    logs: List[TrafficLogEntry]

class SecurityEventEntry(BaseModel):
    id: int
    timestamp: str
    classification: str
    message: str

class SecurityEventsResponse(BaseModel):
    total: int
    events: List[SecurityEventEntry]

class ReportResponse(BaseModel):
    timestamp: str
    content: str

