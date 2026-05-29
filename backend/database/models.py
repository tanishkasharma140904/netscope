# =============================================================
#   NetScope AI — Database Models
#   Declarative models for network assets and security history
# =============================================================

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from datetime import datetime
from backend.database.database import Base

class Host(Base):
    """Network Host Inventory"""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    first_seen = Column(String)
    last_seen = Column(String)
    packet_count = Column(Integer, default=0)
    is_internal = Column(Boolean, default=False)


class SessionRecord(Base):
    """Active Session Activity Tracking Snapshot"""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True, nullable=False)
    destination_ip = Column(String, index=True, nullable=False)
    protocol = Column(String, nullable=False)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)
    duration = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class AlertRecord(Base):
    """Triggered Security Alerts Log"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String, index=True, nullable=False)
    severity = Column(String, nullable=False)
    message = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class ThreatRecord(Base):
    """Network Telemetry Platform Threat Assessment"""
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    threat_name = Column(String, index=True)
    category = Column(String, default="Threat Assessment")
    risk_level = Column(String, nullable=False)
    score = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class StatsSnapshot(Base):
    """Overall Bandwidth & Protocol Statistics Snapshots"""
    __tablename__ = "stats_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    total_packets = Column(Integer, default=0)
    tcp_packets = Column(Integer, default=0)
    udp_packets = Column(Integer, default=0)
    icmp_packets = Column(Integer, default=0)
    other_packets = Column(Integer, default=0)
    total_data = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class ForensicSnapshot(Base):
    """Captured forensic snapshot of current sniffer telemetry state"""
    __tablename__ = "forensic_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    snapshot_name = Column(String, default="Manual Forensic Capture")
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threats_json = Column(String)  # Serialized JSON of threats/alerts
    hosts_json = Column(String)    # Serialized JSON of inventory hosts
    sessions_json = Column(String)  # Serialized JSON of active sessions
    stats_json = Column(String)    # Serialized JSON of statistical snapshot
