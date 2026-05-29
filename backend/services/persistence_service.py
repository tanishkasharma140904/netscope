# =============================================================
#   NetScope AI — Persistence Service
#   Runs a background daemon thread to save snapshots every 30s
# =============================================================

import threading
import time
import sys
import os
from datetime import datetime
from backend.database.database import SessionLocal
from backend.database import crud
from backend.database.init_db import init_db

# Ensure root dir is in sys.path so imports resolve
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from phase1.netscope_phase11_ultimate import (
    lock,
    counters,
    bandwidth,
    ip_tracker,
    port_tracker,
    session_tracker,
    app_tracker,
    network_inventory,
    alerts,
    suspicious_port_hits,
    port_scan_tracker,
    dst_host_tracker,
    calculate_threat_score,
    get_risk_level,
    detect_anomalies,
    is_private_ip,
    format_bytes
)

# Keep track of alerts we've already written to prevent duplicate SQLite insertions
processed_alerts = set()

def parse_alert_string(alert_str):
    """Parses standard Scapy alert strings into alert type, severity, and message details."""
    msg = alert_str
    if "]" in alert_str:
        # Extract everything after "[HH:MM:SS] "
        msg = alert_str.split("]", 1)[1].strip()

    alert_type = "Anomaly"
    msg_lower = msg.lower()
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

    severity = "HIGH"
    if "critical" in msg_lower:
        severity = "CRITICAL"
    elif "medium" in msg_lower:
        severity = "MEDIUM"
    elif "low" in msg_lower:
        severity = "LOW"

    return alert_type, severity, msg

def run_persistence_loop():
    """Main loop executing network telemetry snapshots every 30 seconds."""
    print("   💾  NetScope Database Persistence Thread Started.")
    
    # Initialize DB (Auto-create database and tables on startup)
    init_db()

    while True:
        try:
            # Wait 30 seconds before taking the next snapshot
            time.sleep(30)

            db = SessionLocal()
            try:
                # ---------------------------------------------------------
                # 1. Thread-safe Live Telemetry Capture (Milliseconds Lock)
                # ---------------------------------------------------------
                with lock:
                    # Capture core protocol counters
                    snap_counters = dict(counters)
                    snap_bandwidth = dict(bandwidth)

                    # Capture active inventory
                    snap_inventory = {ip: dict(data) for ip, data in network_inventory.items()}

                    # Capture active sessions
                    snap_sessions = {key: dict(data) for key, data in session_tracker.items()}

                    # Capture alert list
                    snap_alerts = list(alerts)

                    # Gather intelligence inputs for threat computations
                    total = counters["total"]
                    udp = counters["udp"]
                    icmp = counters["icmp"]
                    top_ips = ip_tracker.most_common(10)
                    app_counts = dict(app_tracker)
                    suspicious_hits = dict(suspicious_port_hits)
                    scan_data = {ip: set(ports) for ip, ports in port_scan_tracker.items()}
                    host_data = {ip: set(hosts) for ip, hosts in dst_host_tracker.items()}

                    # Compute live threat posture
                    threat_score = calculate_threat_score(
                        total, udp, icmp, 0, top_ips, app_counts, suspicious_hits, scan_data, host_data
                    )
                    risk_level = get_risk_level(threat_score)
                    active_threats = detect_anomalies(
                        total, udp, icmp, 0, top_ips, app_counts, suspicious_hits, scan_data, host_data
                    )
                    top_threat = active_threats[0] if active_threats else "None"

                # ---------------------------------------------------------
                # 2. Database Writes (Outside Lock - Async/Non-blocking)
                # ---------------------------------------------------------

                # A. Total Protocol statistics
                crud.create_stats_snapshot(
                    db,
                    total_packets=snap_counters["total"],
                    tcp_packets=snap_counters["tcp"],
                    udp_packets=snap_counters["udp"],
                    icmp_packets=snap_counters["icmp"],
                    other_packets=snap_counters["other"],
                    total_data=format_bytes(snap_bandwidth["total_bytes"])
                )

                # B. Network Inventory (Hosts)
                for ip, data in snap_inventory.items():
                    first_seen_str = datetime.fromtimestamp(data["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                    last_seen_str = datetime.fromtimestamp(data["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                    is_internal = is_private_ip(ip)
                    crud.upsert_host(
                        db,
                        ip_address=ip,
                        first_seen=first_seen_str,
                        last_seen=last_seen_str,
                        packet_count=data["packets"],
                        is_internal=is_internal
                    )

                # C. Session Snapshots
                for key, data in snap_sessions.items():
                    duration = round(data["last_seen"] - data["first_seen"], 2)
                    crud.create_session(
                        db,
                        source_ip=key[0],
                        destination_ip=key[1],
                        protocol=key[2],
                        source_port=key[3],
                        destination_port=key[4],
                        packets=data["packets"],
                        bytes=data["bytes"],
                        duration=duration
                    )

                # D. Triggered Security Alerts
                for alert_str in snap_alerts:
                    if alert_str not in processed_alerts:
                        alert_type, severity, msg = parse_alert_string(alert_str)
                        crud.create_alert(
                            db,
                            alert_type=alert_type,
                            severity=severity,
                            message=msg
                        )
                        processed_alerts.add(alert_str)

                # E. Platform Threat Assessment
                crud.create_threat(
                    db,
                    threat_name=top_threat,
                    category="Threat Assessment",
                    risk_level=risk_level,
                    score=threat_score
                )

            except Exception as e:
                print(f"   ⚠️  Database persistence snapshot writing error: {e}")
            finally:
                db.close()

        except Exception as e:
            print(f"   ⚠️  Database persistence thread execution error: {e}")

def start_persistence_service():
    """Initializes and runs the database persistence daemon thread."""
    persistence_thread = threading.Thread(
        target=run_persistence_loop,
        daemon=True,
        name="DatabasePersistence"
    )
    persistence_thread.start()
