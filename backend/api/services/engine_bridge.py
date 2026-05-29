# =============================================================
#   NetScope AI — Engine Bridge Service
#   Provides thread-safe access to live Scapy engine globals
# =============================================================

import sys
import os
from datetime import datetime

# Ensure root directory is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from phase1.netscope_phase11_ultimate import (
    lock,
    counters,
    bandwidth,
    ip_tracker,
    port_tracker,
    COMMON_PORTS,
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
    format_bytes
)

def get_stats():
    """Returns protocol packet counts and total bandwidth data."""
    with lock:
        return {
            "total_packets": counters["total"],
            "tcp_packets": counters["tcp"],
            "udp_packets": counters["udp"],
            "icmp_packets": counters["icmp"],
            "other_packets": counters["other"],
            "total_data": format_bytes(bandwidth["total_bytes"])
        }

def get_top_talkers():
    """Returns the top 10 most active IP addresses."""
    with lock:
        top_ips = ip_tracker.most_common(10)
        return {
            "top_talkers": [
                {
                    "rank": idx + 1,
                    "ip": ip,
                    "packet_count": count
                }
                for idx, (ip, count) in enumerate(top_ips)
            ]
        }

def get_top_ports():
    """Returns the top 10 ports being utilized."""
    with lock:
        top_ports = port_tracker.most_common(10)
        return {
            "top_ports": [
                {
                    "rank": idx + 1,
                    "port": port,
                    "service": COMMON_PORTS.get(port, "UNKNOWN"),
                    "packet_count": count
                }
                for idx, (port, count) in enumerate(top_ports)
            ]
        }

def get_sessions():
    """Returns all active sessions sorted by packets count."""
    with lock:
        sorted_sessions = sorted(
            session_tracker.items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )
        return {
            "session_count": len(session_tracker),
            "active_sessions": [
                {
                    "source_ip": key[0],
                    "destination_ip": key[1],
                    "protocol": key[2],
                    "source_port": key[3],
                    "destination_port": key[4],
                    "packets": data["packets"],
                    "bytes": data["bytes"],
                    "duration": round(data["last_seen"] - data["first_seen"], 2)
                }
                for key, data in sorted_sessions
            ]
        }

def get_threats():
    """Runs anomaly detection and threat scoring to return security posture details."""
    with lock:
        total = counters["total"]
        udp = counters["udp"]
        icmp = counters["icmp"]
        top_ips = ip_tracker.most_common(10)
        app_counts = dict(app_tracker)
        suspicious_hits = dict(suspicious_port_hits)
        scan_data = {ip: set(ports) for ip, ports in port_scan_tracker.items()}
        host_data = {ip: set(hosts) for ip, hosts in dst_host_tracker.items()}
        recent_alerts = list(alerts)

        score = calculate_threat_score(
            total,
            udp,
            icmp,
            0,
            top_ips,
            app_counts,
            suspicious_hits,
            scan_data,
            host_data
        )
        risk = get_risk_level(score)
        active_threats = detect_anomalies(
            total,
            udp,
            icmp,
            0,
            top_ips,
            app_counts,
            suspicious_hits,
            scan_data,
            host_data
        )

        return {
            "threat_score": score,
            "risk_level": risk,
            "active_threats": active_threats,
            "recent_alerts": recent_alerts
        }

def get_inventory():
    """Returns network inventory showing hosts first/last seen and packet counts."""
    with lock:
        hosts_sorted = sorted(
            network_inventory.items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )
        return {
            "host_count": len(network_inventory),
            "hosts": [
                {
                    "ip": ip,
                    "first_seen": datetime.fromtimestamp(data["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.fromtimestamp(data["last_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "packet_count": data["packets"]
                }
                for ip, data in hosts_sorted
            ]
        }

def get_applications():
    """Returns application classification statistics with percentages."""
    with lock:
        total_app_packets = sum(app_tracker.values())
        top_apps = app_tracker.most_common()
        return {
            "applications": [
                {
                    "name": name,
                    "packet_count": count,
                    "percentage": round((count / total_app_packets * 100), 2) if total_app_packets > 0 else 0.0
                }
                for name, count in top_apps
            ]
        }

def get_executive_summary():
    """Provides a summarized, high-level operational overview of security health."""
    with lock:
        total = counters["total"]
        udp = counters["udp"]
        icmp = counters["icmp"]
        top_ips = ip_tracker.most_common(10)
        app_counts = dict(app_tracker)
        suspicious_hits = dict(suspicious_port_hits)
        scan_data = {ip: set(ports) for ip, ports in port_scan_tracker.items()}
        host_data = {ip: set(hosts) for ip, hosts in dst_host_tracker.items()}
        recent_alerts = list(alerts)

        score = calculate_threat_score(
            total,
            udp,
            icmp,
            0,
            top_ips,
            app_counts,
            suspicious_hits,
            scan_data,
            host_data
        )
        risk = get_risk_level(score)
        security_health = max(0, 100 - score)

        active_threats = detect_anomalies(
            total,
            udp,
            icmp,
            0,
            top_ips,
            app_counts,
            suspicious_hits,
            scan_data,
            host_data
        )
        top_threat = active_threats[0] if active_threats else None

        top_app = app_tracker.most_common(1)
        top_application = top_app[0][0] if top_app else None

        return {
            "threat_score": score,
            "risk_level": risk,
            "security_health": security_health,
            "total_hosts": len(network_inventory),
            "total_sessions": len(session_tracker),
            "total_alerts": len(recent_alerts),
            "top_threat": top_threat,
            "top_application": top_application
        }
