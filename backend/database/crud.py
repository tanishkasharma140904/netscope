# =============================================================
#   NetScope AI — CRUD Operations
#   Utility functions for database reads and writes
# =============================================================

from sqlalchemy.orm import Session
from datetime import datetime
from backend.database import models

# =============================================================
#   READ FUNCTIONS (Newest first)
# =============================================================

def get_stats_snapshots(db: Session, limit: int = 100):
    """Retrieve historical protocol statistics snapshots."""
    return db.query(models.StatsSnapshot).order_by(models.StatsSnapshot.id.desc()).limit(limit).all()

def get_alerts(db: Session, limit: int = 100):
    """Retrieve triggered security alerts log."""
    return db.query(models.AlertRecord).order_by(models.AlertRecord.id.desc()).limit(limit).all()

def get_threats(db: Session, limit: int = 100):
    """Retrieve historical threat assessments."""
    return db.query(models.ThreatRecord).order_by(models.ThreatRecord.id.desc()).limit(limit).all()

def get_sessions(db: Session, limit: int = 100):
    """Retrieve historical session tracking logs."""
    return db.query(models.SessionRecord).order_by(models.SessionRecord.id.desc()).limit(limit).all()

def get_hosts(db: Session, limit: int = 100):
    """Retrieve historical registered network hosts inventory."""
    return db.query(models.Host).order_by(models.Host.id.desc()).limit(limit).all()


# =============================================================
#   WRITE FUNCTIONS
# =============================================================

def upsert_host(db: Session, ip_address: str, first_seen: str, last_seen: str, packet_count: int, is_internal: bool):
    """Inserts a host or updates its properties if it already exists."""
    db_host = db.query(models.Host).filter(models.Host.ip_address == ip_address).first()
    if db_host:
        db_host.first_seen = first_seen
        db_host.last_seen = last_seen
        db_host.packet_count = packet_count
        db_host.is_internal = is_internal
    else:
        db_host = models.Host(
            ip_address=ip_address,
            first_seen=first_seen,
            last_seen=last_seen,
            packet_count=packet_count,
            is_internal=is_internal
        )
        db.add(db_host)
    db.commit()
    db.refresh(db_host)
    return db_host

def create_session(db: Session, source_ip: str, destination_ip: str, protocol: str, source_port: int, destination_port: int, packets: int, bytes: int, duration: float):
    """Inserts a new session snapshot record."""
    db_session = models.SessionRecord(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packets=packets,
        bytes=bytes,
        duration=duration
    )
    db.add(db_session)
    db.commit()
    return db_session

def create_alert(db: Session, alert_type: str, severity: str, message: str, timestamp: datetime = None):
    """Inserts a new security alert log."""
    db_alert = models.AlertRecord(
        alert_type=alert_type,
        severity=severity,
        message=message
    )
    if timestamp:
        db_alert.timestamp = timestamp
    db.add(db_alert)
    db.commit()
    return db_alert

def create_threat(db: Session, threat_name: str, category: str, risk_level: str, score: int):
    """Inserts a new threat platform snapshot."""
    db_threat = models.ThreatRecord(
        threat_name=threat_name,
        category=category,
        risk_level=risk_level,
        score=score
    )
    db.add(db_threat)
    db.commit()
    return db_threat

def create_stats_snapshot(db: Session, total_packets: int, tcp_packets: int, udp_packets: int, icmp_packets: int, other_packets: int, total_data: str):
    """Inserts a new statistics snapshot."""
    db_snapshot = models.StatsSnapshot(
        total_packets=total_packets,
        tcp_packets=tcp_packets,
        udp_packets=udp_packets,
        icmp_packets=icmp_packets,
        other_packets=other_packets,
        total_data=total_data
    )
    db.add(db_snapshot)
    db.commit()
    return db_snapshot


def create_forensic_snapshot(db: Session, snapshot_name: str, threats_json: str, hosts_json: str, sessions_json: str, stats_json: str):
    """Inserts a new forensic snapshot."""
    db_snapshot = models.ForensicSnapshot(
        snapshot_name=snapshot_name,
        threats_json=threats_json,
        hosts_json=hosts_json,
        sessions_json=sessions_json,
        stats_json=stats_json
    )
    db.add(db_snapshot)
    db.commit()
    db.refresh(db_snapshot)
    return db_snapshot


def get_forensic_snapshots(db: Session, limit: int = 100):
    """Retrieve all historical forensic snapshots."""
    return db.query(models.ForensicSnapshot).order_by(models.ForensicSnapshot.id.desc()).limit(limit).all()
