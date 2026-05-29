# =============================================================
#   NetScope AI — WebSocket Broadcaster Task
#   Calculates and streams telemetry updates every second
# =============================================================

import asyncio
import time
from datetime import datetime
from backend.websocket.manager import (
    stats_manager,
    threats_manager,
    sessions_manager,
    hosts_manager
)
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
    detect_anomalies
)

async def websocket_broadcaster_loop():
    """Natively runs every 1 second inside FastAPI event loop to broadcast engine data to active sockets."""
    print("   🚀  NetScope WebSocket Broadcaster Task Started successfully.")
    
    last_total_bytes = 0
    last_total_packets = 0
    
    while True:
        try:
            await asyncio.sleep(1)
            
            # 1. Thread-safe Live Telemetry Capture (Milliseconds Lock)
            with lock:
                # Capture counters and bandwidth
                snap_counters = dict(counters)
                snap_bandwidth = dict(bandwidth)
                
                # Compute threat indicators
                total = counters["total"]
                udp = counters["udp"]
                icmp = counters["icmp"]
                top_ips = ip_tracker.most_common(10)
                app_counts = dict(app_tracker)
                suspicious_hits = dict(suspicious_port_hits)
                scan_data = {ip: set(ports) for ip, ports in port_scan_tracker.items()}
                host_data = {ip: set(hosts) for ip, hosts in dst_host_tracker.items()}
                
                threat_score = calculate_threat_score(
                    total, udp, icmp, 0, top_ips, app_counts, suspicious_hits, scan_data, host_data
                )
                risk_level = get_risk_level(threat_score)
                active_threats = detect_anomalies(
                    total, udp, icmp, 0, top_ips, app_counts, suspicious_hits, scan_data, host_data
                )
                
                # Fetch top 10 sessions
                sorted_sessions = sorted(
                    session_tracker.items(),
                    key=lambda x: x[1]["packets"],
                    reverse=True
                )[:10]
                
                # Fetch top discovered network hosts
                sorted_hosts = sorted(
                    network_inventory.items(),
                    key=lambda x: x[1]["packets"],
                    reverse=True
                )[:10]
                
            # 2. Perform Calculations Outside Lock
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            current_bytes = snap_bandwidth["total_bytes"]
            current_packets = snap_counters["total"]
            
            # Dynamic live bps/pps calculations based on real differentials across ticks
            if last_total_bytes > 0:
                bandwidth_bps = max(0, (current_bytes - last_total_bytes) * 8)
            else:
                bandwidth_bps = 0
                
            if last_total_packets > 0:
                packets_per_second = max(0, current_packets - last_total_packets)
            else:
                packets_per_second = 0
                
            last_total_bytes = current_bytes
            last_total_packets = current_packets
            
            # 3. Broadcast Payloads
            print("[WS BROADCAST] sending stats, threats, sessions, and hosts telemetry")
            
            # A. Stats payload
            stats_payload = {
                "timestamp": now_str,
                "total_packets": int(snap_counters["total"]),
                "tcp": int(snap_counters["tcp"]),
                "udp": int(snap_counters["udp"]),
                "icmp": int(snap_counters["icmp"]),
                "bandwidth_bps": int(bandwidth_bps),
                "packets_per_second": int(packets_per_second),
                "threat_score": int(threat_score),
                "risk_level": str(risk_level)
            }
            await stats_manager.broadcast(stats_payload)
            
            # B. Threats payload
            threats_payload = {
                "timestamp": now_str,
                "active_threats": [str(t) for t in active_threats],
                "threat_score": int(threat_score),
                "risk_level": str(risk_level)
            }
            await threats_manager.broadcast(threats_payload)
            
            # C. Sessions payload
            sessions_payload = [
                {
                    "src_ip": str(key[0]),
                    "dst_ip": str(key[1]),
                    "protocol": str(key[2]),
                    "packets": int(data["packets"]),
                    "bytes": int(data["bytes"])
                }
                for key, data in sorted_sessions
            ]
            await sessions_manager.broadcast(sessions_payload)
            
            # D. Discovered Hosts payload
            hosts_payload = [
                {
                    "ip": str(ip),
                    "packets": int(data["packets"]),
                    "first_seen": datetime.fromtimestamp(data["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": datetime.fromtimestamp(data["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                }
                for ip, data in sorted_hosts
            ]
            await hosts_manager.broadcast(hosts_payload)
            
        except Exception as e:
            print(f"[WS BROADCASTER ERROR] WebSocket broadcaster iteration error: {e}")
