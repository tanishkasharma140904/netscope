# =============================================================
#   NetScope AI — Phase 11: Ultimate Edition
#   Project: Real-Time Network Traffic Analyzer
#   Role: Miniature SOC (Security Operations Center)
# =============================================================
#
#   Builds on:
#
#   Phase 1  → Packet Detection
#   Phase 2  → Packet Inspection
#   Phase 3  → Traffic Statistics
#   Phase 4  → Top Talker Analysis
#   Phase 5  → Port Analysis
#   Phase 6  → Bandwidth Monitor
#   Phase 7  → Anomaly Detection Engine
#   Phase 8  → Session Intelligence
#   Phase 9  → Application Intelligence
#   Phase 10 → Threat Intelligence
#
# =============================================================
#
#   NEW IN PHASE 11 — ULTIMATE EDITION
#
#   ✅ Geo Intelligence (Internal / External)
#
#   ✅ Traffic Logging (logs/traffic.log)
#
#   ✅ Security Event Logging (logs/alerts.log)
#
#   ✅ Session Cleanup Engine (300s TTL)
#
#   ✅ Session Analytics (Longest / Largest / Most Active)
#
#   ✅ Security Scoring V2 (Health %)
#
#   ✅ Attack Classification
#
#   ✅ Network Inventory (Host Tracking)
#
#   ✅ Export Report Engine (reports/final_report.txt)
#
#   ✅ Performance Metrics (Uptime, PPS)
#
#   ✅ Executive Security Dashboard
#
# =============================================================
#
#   ARCHITECTURE
#
#       Thread 1 — Packet Sniffer
#       Thread 2 — Statistics Engine
#
#       All data structures protected by a single
#       threading.Lock for thread safety.
#
#       Log files are written outside the lock
#       to avoid I/O blocking the sniffer.
#
# =============================================================
#
#   GEO INTELLIGENCE
#
#   RFC 1918 Private Address Ranges:
#
#       10.0.0.0     – 10.255.255.255
#       172.16.0.0   – 172.31.255.255
#       192.168.0.0  – 192.168.255.255
#
#   Also treated as internal:
#
#       127.0.0.0/8  (loopback)
#
#   Everything else → External
#
# =============================================================
#
#   SESSION CLEANUP
#
#   Sessions inactive for > 300 seconds are
#   automatically removed each refresh cycle.
#
#   This prevents unbounded memory growth
#   during long-running captures.
#
# =============================================================
#
#   ATTACK CLASSIFICATION
#
#   Alerts are mapped to tactical categories:
#
#       Port Scan          → Reconnaissance
#       High ICMP          → Reconnaissance
#       Recon Activity     → Reconnaissance
#       Suspicious Port    → Malware Activity
#       Bandwidth Spike    → Data Transfer Spike
#       Unknown Traffic    → Unknown Activity
#       High UDP           → Protocol Abuse
#       Host Dominance     → Network Dominance
#
# =============================================================
#
#   EXPORT REPORT
#
#   On CTRL+C, a human-readable report is
#   automatically saved to:
#
#       reports/final_report.txt
#
#   This is the final backend artifact before
#   API and dashboard development.
#
# =============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP

import threading
import time
import os
import logging

from datetime import datetime
from collections import Counter
from logging.handlers import RotatingFileHandler


# =============================================================
#   SECTION 1 — PROGRAM START TIME
# =============================================================

PROGRAM_START_TIME = time.time()


# =============================================================
#   SECTION 2 — PROTOCOL COUNTERS
# =============================================================

counters = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
}


# =============================================================
#   SECTION 3 — TOP TALKER TRACKER
# =============================================================

ip_tracker = Counter()


# =============================================================
#   SECTION 4 — PORT TRACKER
# =============================================================

port_tracker = Counter()


# =============================================================
#   SECTION 5 — COMMON PORT DATABASE
# =============================================================

COMMON_PORTS = {

    20: "FTP-DATA",
    21: "FTP",

    22: "SSH",

    23: "TELNET",

    25: "SMTP",

    53: "DNS",

    67: "DHCP",
    68: "DHCP",

    80: "HTTP",

    110: "POP3",

    123: "NTP",

    143: "IMAP",

    161: "SNMP",

    443: "HTTPS",

    465: "SMTPS",

    587: "SMTP",

    993: "IMAPS",

    995: "POP3S",

    3306: "MYSQL",

    3389: "RDP",

    5432: "POSTGRESQL",

    6379: "REDIS",

    8080: "HTTP-ALT",
}


# =============================================================
#   SECTION 6 — BANDWIDTH TRACKER
# =============================================================

bandwidth = {

    "total_bytes": 0,

    "window_bytes": 0,

    "window_packets": 0,

    "window_start": time.time(),
}


# =============================================================
#   SECTION 7 — ALERT HISTORY
# =============================================================

alerts = []

MAX_ALERTS = 20


# =============================================================
#   SECTION 8 — DETECTION THRESHOLDS
# =============================================================

UDP_THRESHOLD = 70

ICMP_THRESHOLD = 20

BANDWIDTH_THRESHOLD = 500000

HOST_DOMINANCE_THRESHOLD = 80

UNKNOWN_APP_THRESHOLD = 30

PORT_SCAN_THRESHOLD = 20

RECON_ICMP_THRESHOLD = 15

RECON_HOSTS_THRESHOLD = 10

SESSION_TIMEOUT = 300


# =============================================================
#   SECTION 9 — SESSION TRACKER (PHASE 8)
# =============================================================

session_tracker = {}

expired_session_count = 0


# =============================================================
#   SECTION 10 — APPLICATION INTELLIGENCE (PHASE 9)
# =============================================================

app_tracker = Counter()

APP_PORT_MAP = {

    443:  "HTTPS",

    80:   "HTTP",

    53:   "DNS",

    22:   "SSH",

    25:   "SMTP",

    110:  "POP3",

    143:  "IMAP",

    123:  "NTP",

    67:   "DHCP",
    68:   "DHCP",

    21:   "FTP",

    3306: "MYSQL",

    5432: "POSTGRESQL",

    6379: "REDIS",
}


# =============================================================
#   SECTION 11 — SUSPICIOUS PORT DATABASE (PHASE 10)
# =============================================================

SUSPICIOUS_PORTS = {

    4444,

    5555,

    6666,

    1337,

    31337,

    12345,
}


# =============================================================
#   SECTION 12 — PORT SCAN TRACKER (PHASE 10)
# =============================================================

port_scan_tracker = {}


# =============================================================
#   SECTION 13 — DESTINATION HOST TRACKER (PHASE 10)
# =============================================================

dst_host_tracker = {}


# =============================================================
#   SECTION 14 — SUSPICIOUS PORT HIT TRACKER (PHASE 10)
# =============================================================

suspicious_port_hits = Counter()


# =============================================================
#   SECTION 15 — GEO INTELLIGENCE (PHASE 11)
# =============================================================
#
# Counters for internal vs external traffic.
#
# external_ip_tracker records packet counts for
# each external IP to identify top external hosts.
#
# =============================================================

geo_counters = {

    "internal": 0,

    "external": 0,
}

external_ip_tracker = Counter()


# =============================================================
#   SECTION 16 — NETWORK INVENTORY (PHASE 11)
# =============================================================
#
# Tracks every host seen on the network.
#
# Structure:
#
#   {
#       "192.168.1.60": {
#           "first_seen": <timestamp>,
#           "last_seen":  <timestamp>,
#           "packets":    <count>
#       }
#   }
#
# =============================================================

network_inventory = {}


# =============================================================
#   SECTION 17 — ATTACK CLASSIFICATION MAP (PHASE 11)
# =============================================================
#
# Maps alert keywords to tactical categories.
#
# =============================================================

ATTACK_CLASSIFICATION = {

    "PORT SCAN":
        "Reconnaissance",

    "HIGH ICMP":
        "Reconnaissance",

    "RECONNAISSANCE":
        "Reconnaissance",

    "SUSPICIOUS PORT":
        "Malware Activity",

    "BANDWIDTH SPIKE":
        "Data Transfer Spike",

    "UNKNOWN TRAFFIC":
        "Unknown Activity",

    "HIGH UDP":
        "Protocol Abuse",

    "HOST DOMINANCE":
        "Network Dominance",
}


# =============================================================
#   SECTION 18 — LOGGING SETUP (PHASE 11)
# =============================================================
#
# Creates logs/ directory and configures
# rotating file handlers for:
#
#   logs/traffic.log  — packet-level events
#   logs/alerts.log   — security alerts
#
# Rotation: 5 MB per file, 3 backups.
#
# =============================================================

LOGS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "logs"
)

os.makedirs(LOGS_DIR, exist_ok=True)

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports"
)

os.makedirs(REPORTS_DIR, exist_ok=True)

# --- Traffic Logger ---

traffic_logger = logging.getLogger("traffic")

traffic_logger.setLevel(logging.INFO)

traffic_handler = RotatingFileHandler(

    os.path.join(LOGS_DIR, "traffic.log"),

    maxBytes=5 * 1024 * 1024,

    backupCount=3
)

traffic_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(message)s"
    )
)

traffic_logger.addHandler(traffic_handler)

# --- Alert Logger ---

alert_logger = logging.getLogger("alerts")

alert_logger.setLevel(logging.WARNING)

alert_handler = RotatingFileHandler(

    os.path.join(LOGS_DIR, "alerts.log"),

    maxBytes=5 * 1024 * 1024,

    backupCount=3
)

alert_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s | %(message)s"
    )
)

alert_logger.addHandler(alert_handler)


# =============================================================
#   SECTION 19 — THREAD LOCK
# =============================================================

lock = threading.Lock()


# =============================================================
#   HELPER FUNCTION — is_private_ip()
# =============================================================
#
# Determines if an IP is in RFC1918 private range
# or loopback.
#
#   10.0.0.0/8
#   172.16.0.0/12
#   192.168.0.0/16
#   127.0.0.0/8
#
# =============================================================

def is_private_ip(ip_str):

    parts = ip_str.split(".")

    if len(parts) != 4:
        return False

    try:

        a = int(parts[0])
        b = int(parts[1])

    except ValueError:

        return False

    # 10.x.x.x
    if a == 10:
        return True

    # 172.16.x.x – 172.31.x.x
    if a == 172 and 16 <= b <= 31:
        return True

    # 192.168.x.x
    if a == 192 and b == 168:
        return True

    # 127.x.x.x (loopback)
    if a == 127:
        return True

    return False


# =============================================================
#   HELPER FUNCTION — classify_application()
# =============================================================

def classify_application(src_port, dst_port):

    if dst_port in APP_PORT_MAP:

        return APP_PORT_MAP[dst_port]

    if src_port in APP_PORT_MAP:

        return APP_PORT_MAP[src_port]

    return "OTHER"


# =============================================================
#   HELPER FUNCTION — build_session_key()
# =============================================================

def build_session_key(
    src_ip,
    dst_ip,
    protocol,
    src_port,
    dst_port
):

    return (
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port
    )


# =============================================================
#   HELPER FUNCTION — get_risk_level()
# =============================================================

def get_risk_level(score):

    if score <= 20:

        return "LOW"

    elif score <= 40:

        return "MEDIUM"

    elif score <= 70:

        return "HIGH"

    else:

        return "CRITICAL"


# =============================================================
#   HELPER FUNCTION — format_bytes()
# =============================================================

def format_bytes(num_bytes):

    KB = 1024
    MB = 1024 ** 2
    GB = 1024 ** 3

    if num_bytes >= GB:

        return f"{num_bytes / GB:.2f} GB"

    elif num_bytes >= MB:

        return f"{num_bytes / MB:.2f} MB"

    elif num_bytes >= KB:

        return f"{num_bytes / KB:.2f} KB"

    else:

        return f"{int(num_bytes)} B"


# =============================================================
#   HELPER FUNCTION — make_bar()
# =============================================================

def make_bar(count, max_count, bar_width=20):

    if max_count == 0:

        return " " * bar_width

    filled = int(
        (count / max_count) * bar_width
    )

    empty = bar_width - filled

    return (
        "█" * filled
        +
        "░" * empty
    )


# =============================================================
#   HELPER FUNCTION — format_uptime()
# =============================================================
#
# Converts seconds into human-readable uptime.
#
# Example:
#
#   3661 → "1h 1m 1s"
#
# =============================================================

def format_uptime(seconds):

    hours = int(seconds // 3600)

    minutes = int((seconds % 3600) // 60)

    secs = int(seconds % 60)

    if hours > 0:

        return f"{hours}h {minutes}m {secs}s"

    elif minutes > 0:

        return f"{minutes}m {secs}s"

    else:

        return f"{secs}s"


# =============================================================
#   HELPER FUNCTION — classify_attack()
# =============================================================
#
# Maps an alert message to a tactical category
# using the ATTACK_CLASSIFICATION map.
#
# =============================================================

def classify_attack(alert_message):

    for keyword, category in (
        ATTACK_CLASSIFICATION.items()
    ):

        if keyword in alert_message.upper():

            return category

    return "Other"


# =============================================================
#   FUNCTION: add_alert()
# =============================================================

def add_alert(message):

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )

    entry = f"[{timestamp}] {message}"

    alerts.append(entry)

    if len(alerts) > MAX_ALERTS:

        alerts.pop(0)

    # Write to alerts.log
    alert_logger.warning(message)


# =============================================================
#   FUNCTION: log_packet()
# =============================================================
#
# Writes a packet record to traffic.log.
#
# Called outside the lock to avoid blocking.
#
# =============================================================

def log_packet(
    src_ip,
    dst_ip,
    protocol,
    src_port,
    dst_port,
    packet_size
):

    traffic_logger.info(

        f"{src_ip} -> {dst_ip} | "
        f"{protocol} | "
        f"{src_port} -> {dst_port} | "
        f"{packet_size} bytes"

    )


# =============================================================
#   FUNCTION: cleanup_sessions()
# =============================================================
#
# Removes sessions that have been inactive for
# more than SESSION_TIMEOUT seconds.
#
# Called inside the lock.
#
# Returns the number of expired sessions removed.
#
# =============================================================

def cleanup_sessions():

    global expired_session_count

    current_time = time.time()

    expired_keys = []

    for key, data in session_tracker.items():

        idle_time = (
            current_time - data["last_seen"]
        )

        if idle_time > SESSION_TIMEOUT:

            expired_keys.append(key)

    for key in expired_keys:

        del session_tracker[key]

    expired_session_count += len(expired_keys)

    return len(expired_keys)


# =============================================================
#   FUNCTION: analyze_packet(packet)
# =============================================================
#
#   Called by Scapy for EVERY packet captured.
#
#   Responsibilities:
#
#       Phase 3  → Protocol Counters
#       Phase 4  → IP Tracking
#       Phase 5  → Port Tracking
#       Phase 6  → Bandwidth Tracking
#       Phase 7  → Anomaly data
#       Phase 8  → Session Tracking
#       Phase 9  → Application Classification
#       Phase 10 → Suspicious Port / Scan / Recon
#       Phase 11 → Geo Intelligence
#                  Network Inventory
#                  Traffic Logging
#
# =============================================================

def analyze_packet(packet):

    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    packet_size = len(packet)

    with lock:

        # =====================================================
        # PROTOCOL COUNTERS
        # =====================================================

        counters["total"] += 1

        if packet.haslayer(TCP):

            counters["tcp"] += 1

        elif packet.haslayer(UDP):

            counters["udp"] += 1

        elif packet.haslayer(ICMP):

            counters["icmp"] += 1

        else:

            counters["other"] += 1

        # =====================================================
        # TOP TALKER ANALYSIS
        # =====================================================

        ip_tracker[src_ip] += 1
        ip_tracker[dst_ip] += 1

        # =====================================================
        # PORT ANALYSIS
        # =====================================================

        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            port_tracker[tcp_layer.sport] += 1
            port_tracker[tcp_layer.dport] += 1

        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            port_tracker[udp_layer.sport] += 1
            port_tracker[udp_layer.dport] += 1

        # =====================================================
        # BANDWIDTH TRACKING
        # =====================================================

        bandwidth["total_bytes"] += packet_size

        bandwidth["window_bytes"] += packet_size

        bandwidth["window_packets"] += 1

        # ======================================================
        # PHASE 8 — SESSION TRACKING
        # ======================================================

        protocol = "OTHER"
        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):

            protocol = "TCP"

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):

            protocol = "UDP"

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        session_key = build_session_key(
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port
        )

        current_time = time.time()

        if session_key not in session_tracker:

            session_tracker[session_key] = {

                "packets": 0,
                "bytes": 0,

                "first_seen": current_time,
                "last_seen": current_time

            }

        session_tracker[session_key]["packets"] += 1

        session_tracker[session_key]["bytes"] += packet_size

        session_tracker[session_key]["last_seen"] = current_time

        # ======================================================
        # PHASE 9 — APPLICATION CLASSIFICATION
        # ======================================================

        if packet.haslayer(TCP) or packet.haslayer(UDP):

            app_name = classify_application(
                src_port,
                dst_port
            )

            app_tracker[app_name] += 1

        # ======================================================
        # PHASE 10 — SUSPICIOUS PORT DETECTION
        # ======================================================

        if src_port in SUSPICIOUS_PORTS:

            suspicious_port_hits[src_port] += 1

        if dst_port in SUSPICIOUS_PORTS:

            suspicious_port_hits[dst_port] += 1

        # ======================================================
        # PHASE 10 — PORT SCAN TRACKING
        # ======================================================

        if packet.haslayer(TCP) or packet.haslayer(UDP):

            if src_ip not in port_scan_tracker:

                port_scan_tracker[src_ip] = set()

            port_scan_tracker[src_ip].add(dst_port)

        # ======================================================
        # PHASE 10 — DESTINATION HOST TRACKING
        # ======================================================

        if src_ip not in dst_host_tracker:

            dst_host_tracker[src_ip] = set()

        dst_host_tracker[src_ip].add(dst_ip)

        # ======================================================
        # PHASE 11 — GEO INTELLIGENCE
        # ======================================================

        src_private = is_private_ip(src_ip)
        dst_private = is_private_ip(dst_ip)

        if src_private and dst_private:

            geo_counters["internal"] += 1

        else:

            geo_counters["external"] += 1

            if not src_private:

                external_ip_tracker[src_ip] += 1

            if not dst_private:

                external_ip_tracker[dst_ip] += 1

        # ======================================================
        # PHASE 11 — NETWORK INVENTORY
        # ======================================================

        for ip_addr in (src_ip, dst_ip):

            if ip_addr not in network_inventory:

                network_inventory[ip_addr] = {

                    "first_seen": current_time,
                    "last_seen": current_time,
                    "packets": 0

                }

            network_inventory[ip_addr]["last_seen"] = (
                current_time
            )

            network_inventory[ip_addr]["packets"] += 1

    # ==========================================================
    # TRAFFIC LOGGING (outside lock)
    # ==========================================================

    log_packet(
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        packet_size
    )


# =============================================================
#   FUNCTION: detect_anomalies()
# =============================================================
#
#   Detection Rules:
#
#   Rule 1  → UDP > 70%
#   Rule 2  → ICMP > 20%
#   Rule 3  → Bandwidth > 500 KB/sec
#   Rule 4  → Single Host > 80%
#   Rule 5  → OTHER app traffic > 30%
#   Rule 6  → Suspicious port traffic
#   Rule 7  → Port scan (> 20 unique dst ports)
#   Rule 8  → Reconnaissance activity
#
# =============================================================

def detect_anomalies(

    total,
    udp,
    icmp,
    bytes_per_sec,
    top_ips,
    app_counts,
    suspicious_hits,
    scan_data,
    host_data

):

    current_alerts = []

    # =========================================================
    # RULE 1 — HIGH UDP TRAFFIC
    # =========================================================

    if total > 0:

        udp_pct = (udp / total) * 100

        if udp_pct > UDP_THRESHOLD:

            current_alerts.append(
                "⚠ HIGH UDP TRAFFIC DETECTED"
            )

    # =========================================================
    # RULE 2 — HIGH ICMP TRAFFIC
    # =========================================================

    if total > 0:

        icmp_pct = (icmp / total) * 100

        if icmp_pct > ICMP_THRESHOLD:

            current_alerts.append(
                "⚠ HIGH ICMP TRAFFIC DETECTED"
            )

    # =========================================================
    # RULE 3 — BANDWIDTH SPIKE
    # =========================================================

    if bytes_per_sec > BANDWIDTH_THRESHOLD:

        current_alerts.append(
            "⚠ BANDWIDTH SPIKE DETECTED"
        )

    # =========================================================
    # RULE 4 — HOST DOMINANCE
    # =========================================================

    if top_ips and total > 0:

        top_ip_count = top_ips[0][1]

        host_pct = (top_ip_count / total) * 100

        if host_pct > HOST_DOMINANCE_THRESHOLD:

            current_alerts.append(
                "⚠ HOST DOMINANCE DETECTED"
            )

    # =========================================================
    # RULE 5 — EXCESSIVE UNKNOWN TRAFFIC
    # =========================================================

    total_app_packets = sum(app_counts.values())

    if total_app_packets > 0:

        other_count = app_counts.get("OTHER", 0)

        other_pct = (
            other_count / total_app_packets
        ) * 100

        if other_pct > UNKNOWN_APP_THRESHOLD:

            current_alerts.append(
                "⚠ EXCESSIVE UNKNOWN TRAFFIC DETECTED"
            )

    # =========================================================
    # RULE 6 — SUSPICIOUS PORT
    # =========================================================

    if sum(suspicious_hits.values()) > 0:

        current_alerts.append(
            "⚠ SUSPICIOUS PORT DETECTED"
        )

    # =========================================================
    # RULE 7 — PORT SCAN
    # =========================================================

    for src_ip, ports in scan_data.items():

        if len(ports) > PORT_SCAN_THRESHOLD:

            current_alerts.append(
                "⚠ POSSIBLE PORT SCAN DETECTED"
            )

            break

    # =========================================================
    # RULE 8 — RECONNAISSANCE
    # =========================================================

    recon_detected = False

    if total > 0:

        icmp_pct = (icmp / total) * 100

        if icmp_pct > RECON_ICMP_THRESHOLD:

            for src_ip, hosts in host_data.items():

                if len(hosts) > RECON_HOSTS_THRESHOLD:

                    recon_detected = True

                    break

    if recon_detected:

        current_alerts.append(
            "⚠ RECONNAISSANCE ACTIVITY DETECTED"
        )

    # =========================================================
    # STORE ALERT HISTORY
    # =========================================================

    for alert in current_alerts:

        add_alert(alert)

    return current_alerts


# =============================================================
#   FUNCTION: calculate_threat_score()
# =============================================================

def calculate_threat_score(

    total,
    udp,
    icmp,
    bytes_per_sec,
    top_ips,
    app_counts,
    suspicious_hits,
    scan_data,
    host_data

):

    score = 0

    # Host Dominance → +15
    if top_ips and total > 0:

        top_ip_count = top_ips[0][1]
        host_pct = (top_ip_count / total) * 100

        if host_pct > HOST_DOMINANCE_THRESHOLD:
            score += 15

    # High ICMP → +15
    if total > 0:

        icmp_pct = (icmp / total) * 100

        if icmp_pct > ICMP_THRESHOLD:
            score += 15

    # High UDP → +15
    if total > 0:

        udp_pct = (udp / total) * 100

        if udp_pct > UDP_THRESHOLD:
            score += 15

    # Bandwidth Spike → +20
    if bytes_per_sec > BANDWIDTH_THRESHOLD:
        score += 20

    # Unknown Traffic → +15
    total_app_packets = sum(app_counts.values())

    if total_app_packets > 0:

        other_count = app_counts.get("OTHER", 0)
        other_pct = (
            other_count / total_app_packets
        ) * 100

        if other_pct > UNKNOWN_APP_THRESHOLD:
            score += 15

    # Suspicious Port → +20
    if sum(suspicious_hits.values()) > 0:
        score += 20

    # Port Scan → +30
    for src_ip, ports in scan_data.items():

        if len(ports) > PORT_SCAN_THRESHOLD:
            score += 30
            break

    # Recon Activity → +30
    if total > 0:

        icmp_pct = (icmp / total) * 100

        if icmp_pct > RECON_ICMP_THRESHOLD:

            for src_ip, hosts in host_data.items():

                if len(hosts) > RECON_HOSTS_THRESHOLD:
                    score += 30
                    break

    # Cap at 100
    if score > 100:
        score = 100

    return score


# =============================================================
#   FUNCTION: generate_report()
# =============================================================
#
# Generates a human-readable final report
# saved to reports/final_report.txt.
#
# Called on CTRL+C shutdown.
#
# =============================================================

def generate_report(

    total, tcp, udp, icmp, other,
    top_ips, top_ports, top_apps,
    app_counts, threat_score, risk_level,
    security_health, active_alerts,
    top_sessions, geo_data, inventory_snapshot

):

    report_path = os.path.join(
        REPORTS_DIR,
        "final_report.txt"
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    uptime = time.time() - PROGRAM_START_TIME

    lines = []

    lines.append("=" * 56)
    lines.append(
        "   NETSCOPE AI — FINAL SECURITY REPORT"
    )
    lines.append("=" * 56)
    lines.append(
        f"   Generated : {timestamp}"
    )
    lines.append(
        f"   Uptime    : {format_uptime(uptime)}"
    )
    lines.append("=" * 56)

    # --- Traffic Statistics ---
    lines.append("")
    lines.append("   TRAFFIC STATISTICS")
    lines.append("   " + "─" * 40)
    lines.append(
        f"   Total Packets  : {total}"
    )

    def pct(v):
        return (v / total * 100) if total > 0 else 0.0

    lines.append(
        f"   TCP            : {tcp} ({pct(tcp):.1f}%)"
    )
    lines.append(
        f"   UDP            : {udp} ({pct(udp):.1f}%)"
    )
    lines.append(
        f"   ICMP           : {icmp} ({pct(icmp):.1f}%)"
    )
    lines.append(
        f"   Other          : {other} ({pct(other):.1f}%)"
    )
    lines.append(
        f"   Total Data     : "
        f"{format_bytes(bandwidth['total_bytes'])}"
    )

    # --- Top Hosts ---
    lines.append("")
    lines.append("   TOP HOSTS")
    lines.append("   " + "─" * 40)

    for rank, (ip, count) in enumerate(
        top_ips[:10], start=1
    ):
        lines.append(
            f"   {rank:<3} {ip:<18} {count} packets"
        )

    # --- Top Ports ---
    lines.append("")
    lines.append("   TOP PORTS")
    lines.append("   " + "─" * 40)

    for rank, (port, count) in enumerate(
        top_ports[:10], start=1
    ):
        service = COMMON_PORTS.get(port, "UNKNOWN")
        lines.append(
            f"   {rank:<3} {port:<6} {service:<12} {count}"
        )

    # --- Applications ---
    lines.append("")
    lines.append("   APPLICATIONS")
    lines.append("   " + "─" * 40)

    total_app = sum(app_counts.values())

    for rank, (app, count) in enumerate(
        top_apps[:10], start=1
    ):
        apct = (count / total_app * 100) if total_app > 0 else 0.0
        lines.append(
            f"   {rank:<3} {app:<14} {count:<6} {apct:5.1f}%"
        )

    # --- Sessions ---
    lines.append("")
    lines.append("   TOP SESSIONS")
    lines.append("   " + "─" * 40)

    for skey, sdata in top_sessions[:5]:

        (s_ip, d_ip, proto, sp, dp) = skey

        dur = sdata["last_seen"] - sdata["first_seen"]

        lines.append(
            f"   {s_ip} -> {d_ip} | "
            f"{proto} {sp}->{dp} | "
            f"{sdata['packets']} pkts | "
            f"{format_bytes(sdata['bytes'])} | "
            f"{dur:.1f}s"
        )

    # --- Geo Intelligence ---
    lines.append("")
    lines.append("   GEO INTELLIGENCE")
    lines.append("   " + "─" * 40)
    lines.append(
        f"   Internal Connections : "
        f"{geo_data['internal']}"
    )
    lines.append(
        f"   External Connections : "
        f"{geo_data['external']}"
    )

    # --- Network Inventory ---
    lines.append("")
    lines.append("   NETWORK INVENTORY")
    lines.append("   " + "─" * 40)
    lines.append(
        f"   Total Known Hosts : "
        f"{len(inventory_snapshot)}"
    )

    sorted_inv = sorted(
        inventory_snapshot.items(),
        key=lambda x: x[1]["packets"],
        reverse=True
    )[:10]

    for ip, data in sorted_inv:

        fs = datetime.fromtimestamp(
            data["first_seen"]
        ).strftime("%H:%M:%S")

        ls = datetime.fromtimestamp(
            data["last_seen"]
        ).strftime("%H:%M:%S")

        lines.append(
            f"   {ip:<18} "
            f"{data['packets']:<6} pkts  "
            f"first: {fs}  last: {ls}"
        )

    # --- Security Summary ---
    lines.append("")
    lines.append("   SECURITY SUMMARY")
    lines.append("   " + "─" * 40)
    lines.append(
        f"   Threat Score     : {threat_score}/100"
    )
    lines.append(
        f"   Risk Level       : {risk_level}"
    )
    lines.append(
        f"   Security Health  : {security_health}%"
    )
    lines.append(
        f"   Total Alerts     : {len(alerts)}"
    )

    # --- Active Threats ---
    lines.append("")
    lines.append("   ACTIVE THREATS")
    lines.append("   " + "─" * 40)

    if active_alerts:
        for alert in active_alerts:
            lines.append(f"   {alert}")
    else:
        lines.append("   No active threats")

    # --- Alert History ---
    lines.append("")
    lines.append("   ALERT HISTORY")
    lines.append("   " + "─" * 40)

    if alerts:
        for entry in alerts[-10:]:
            lines.append(f"   {entry}")
    else:
        lines.append("   No alerts generated")

    lines.append("")
    lines.append("=" * 56)
    lines.append(
        "   END OF REPORT"
    )
    lines.append("=" * 56)

    report_content = "\n".join(lines)

    with open(report_path, "w") as f:
        f.write(report_content)

    return report_path


# =============================================================
#   FUNCTION: print_stats()
# =============================================================
#
#   Central Reporting Engine
#
#   Dashboard Blocks:
#
#       1  → Protocol Statistics
#       2  → Top Active IPs
#       3  → Top Ports
#       4  → Bandwidth Monitor
#       5  → Top Active Sessions
#       6  → Session Analytics
#       7  → Application Intelligence
#       8  → Geo Intelligence
#       9  → Network Inventory
#       10 → Threat Intelligence Dashboard
#       11 → Top Threats
#       12 → Attack Classification
#       13 → Anomaly Detection Engine
#       14 → Alert History
#       15 → Performance Metrics
#       16 → Executive Security Summary
#
# =============================================================

def print_stats():

    with lock:

        total = counters["total"]
        tcp = counters["tcp"]
        udp = counters["udp"]
        icmp = counters["icmp"]
        other = counters["other"]

        top_ips = ip_tracker.most_common(10)

        top_ports = port_tracker.most_common(10)

        # --- Session snapshot ---
        top_sessions = sorted(
            session_tracker.items(),
            key=lambda item: item[1]["packets"],
            reverse=True
        )[:5]

        # --- All sessions for analytics ---
        all_sessions = list(
            session_tracker.items()
        )

        session_count = len(session_tracker)

        # --- Session cleanup ---
        removed = cleanup_sessions()

        # --- Application snapshot ---
        app_counts = dict(app_tracker)
        top_apps = app_tracker.most_common(10)

        # --- Threat data snapshot ---
        suspicious_hits = dict(
            suspicious_port_hits
        )

        scan_data = {
            ip: set(ports)
            for ip, ports
            in port_scan_tracker.items()
        }

        host_data = {
            ip: set(hosts)
            for ip, hosts
            in dst_host_tracker.items()
        }

        # --- Geo snapshot ---
        geo_data = dict(geo_counters)

        top_external = external_ip_tracker.most_common(5)

        # --- Network inventory snapshot ---
        inventory_snapshot = {
            ip: dict(data)
            for ip, data
            in network_inventory.items()
        }

        # --- Bandwidth window ---
        total_bytes = bandwidth["total_bytes"]
        window_bytes = bandwidth["window_bytes"]
        window_packets = bandwidth["window_packets"]
        window_start = bandwidth["window_start"]

        bandwidth["window_bytes"] = 0
        bandwidth["window_packets"] = 0
        bandwidth["window_start"] = time.time()

    # =========================================================
    # BANDWIDTH CALCULATIONS
    # =========================================================

    now = time.time()

    elapsed = now - window_start

    if elapsed > 0:

        bytes_per_sec = window_bytes / elapsed
        packets_per_sec = window_packets / elapsed

    else:

        bytes_per_sec = 0
        packets_per_sec = 0

    # =========================================================
    # ANOMALY DETECTION
    # =========================================================

    active_alerts = detect_anomalies(

        total, udp, icmp,
        bytes_per_sec, top_ips,
        app_counts, suspicious_hits,
        scan_data, host_data

    )

    # =========================================================
    # THREAT SCORE & SECURITY HEALTH
    # =========================================================

    threat_score = calculate_threat_score(

        total, udp, icmp,
        bytes_per_sec, top_ips,
        app_counts, suspicious_hits,
        scan_data, host_data

    )

    risk_level = get_risk_level(threat_score)

    security_health = 100 - threat_score

    # =========================================================
    # SESSION ANALYTICS
    # =========================================================

    longest_session = None
    largest_session = None
    most_active_session = None

    if all_sessions:

        longest_session = max(
            all_sessions,
            key=lambda x: (
                x[1]["last_seen"] - x[1]["first_seen"]
            )
        )

        largest_session = max(
            all_sessions,
            key=lambda x: x[1]["bytes"]
        )

        most_active_session = max(
            all_sessions,
            key=lambda x: x[1]["packets"]
        )

    # =========================================================
    # ATTACK CLASSIFICATION
    # =========================================================

    attack_categories = {}

    for alert in active_alerts:

        category = classify_attack(alert)

        if category not in attack_categories:
            attack_categories[category] = []

        attack_categories[category].append(alert)

    # =========================================================
    # DISPLAY
    # =========================================================

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )

    def pct(value):
        return (
            value / total * 100
        ) if total > 0 else 0.0

    uptime = now - PROGRAM_START_TIME

    # =========================================================
    # BLOCK 1 — PROTOCOL STATISTICS
    # =========================================================

    print("\n" + "═" * 56)

    print(
        "   📊  NETSCOPE AI — LIVE STATISTICS"
    )

    print(
        f"   🕐  Snapshot at : {timestamp}"
    )

    print("═" * 56)

    print(f"   Total Packets  : {total}")

    print(
        f"   TCP  Packets   : "
        f"{tcp:<6} ({pct(tcp):.1f}%)"
    )

    print(
        f"   UDP  Packets   : "
        f"{udp:<6} ({pct(udp):.1f}%)"
    )

    print(
        f"   ICMP Packets   : "
        f"{icmp:<6} ({pct(icmp):.1f}%)"
    )

    print(
        f"   Other Packets  : "
        f"{other:<6} ({pct(other):.1f}%)"
    )

    # =========================================================
    # BLOCK 2 — TOP TALKERS
    # =========================================================

    print("═" * 56)
    print("   🏆  TOP 10 ACTIVE IP ADDRESSES")
    print("═" * 56)

    if not top_ips:

        print("   ⏳  Waiting for IP traffic...")

    else:

        max_ip_count = top_ips[0][1]

        for rank, (ip, count) in enumerate(
            top_ips, start=1
        ):

            bar = make_bar(count, max_ip_count)

            print(
                f"   {rank:<3} "
                f"{ip:<18} "
                f"{bar} "
                f"{count}"
            )

    # =========================================================
    # BLOCK 3 — TOP PORTS
    # =========================================================

    print("═" * 56)
    print("   🚪  TOP 10 PORTS")
    print("═" * 56)

    if not top_ports:

        print("   ⏳ Waiting for TCP/UDP traffic...")

    else:

        max_port_count = top_ports[0][1]

        for rank, (port, count) in enumerate(
            top_ports, start=1
        ):

            service = COMMON_PORTS.get(
                port, "UNKNOWN"
            )

            bar = make_bar(count, max_port_count)

            print(
                f"   {rank:<3} "
                f"{port:<6} "
                f"{service:<12} "
                f"{bar} "
                f"{count}"
            )

    # =========================================================
    # BLOCK 4 — BANDWIDTH MONITOR
    # =========================================================

    print("═" * 56)
    print("   📡  BANDWIDTH MONITOR")
    print("═" * 56)

    print(
        f"   Current Speed  : "
        f"{format_bytes(bytes_per_sec)}/s"
    )

    print(
        f"   Bytes/sec      : "
        f"{bytes_per_sec:,.0f}"
    )

    print(
        f"   Packets/sec    : "
        f"{packets_per_sec:.1f}"
    )

    print(
        f"   Total Data     : "
        f"{format_bytes(total_bytes)}"
    )

    # =========================================================
    # BLOCK 5 — TOP ACTIVE SESSIONS
    # =========================================================

    print("═" * 56)
    print("   🔗  TOP ACTIVE SESSIONS")
    print("═" * 56)

    if not top_sessions:

        print("   ⏳  No active sessions yet.")

    else:

        for session_key, data in top_sessions:

            (
                src_ip, dst_ip,
                protocol, src_port, dst_port
            ) = session_key

            duration = (
                data["last_seen"]
                - data["first_seen"]
            )

            print()
            print(f"   {src_ip}")
            print(f"      → {dst_ip}")
            print()
            print(f"   {protocol}")
            print(f"   {src_port} → {dst_port}")
            print()
            print(
                f"   Packets  : {data['packets']}"
            )
            print(
                f"   Bytes    : "
                f"{format_bytes(data['bytes'])}"
            )
            print(
                f"   Duration : {duration:.1f} sec"
            )
            print()
            print("   " + "─" * 32)

    print("═" * 56)

    # =========================================================
    # BLOCK 6 — SESSION ANALYTICS (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   📈  SESSION ANALYTICS")
    print("═" * 56)

    print(
        f"   Active Sessions   : {session_count}"
    )

    print(
        f"   Expired Removed   : {removed}"
    )

    print(
        f"   Total Expired     : "
        f"{expired_session_count}"
    )

    if longest_session:

        lkey, ldata = longest_session

        ldur = (
            ldata["last_seen"]
            - ldata["first_seen"]
        )

        print(
            f"   Longest Session   : "
            f"{lkey[0]} → {lkey[1]} "
            f"({ldur:.1f}s)"
        )

    if largest_session:

        bkey, bdata = largest_session

        print(
            f"   Largest Session   : "
            f"{bkey[0]} → {bkey[1]} "
            f"({format_bytes(bdata['bytes'])})"
        )

    if most_active_session:

        akey, adata = most_active_session

        print(
            f"   Most Active       : "
            f"{akey[0]} → {akey[1]} "
            f"({adata['packets']} pkts)"
        )

    print("═" * 56)

    # =========================================================
    # BLOCK 7 — APPLICATION INTELLIGENCE
    # =========================================================

    print("═" * 56)
    print("   🧠  APPLICATION INTELLIGENCE")
    print("═" * 56)

    total_app_packets = sum(app_counts.values())

    if not top_apps:

        print(
            "   ⏳  Waiting for application traffic..."
        )

    else:

        max_app_count = top_apps[0][1]

        for rank, (app_name, count) in enumerate(
            top_apps, start=1
        ):

            if total_app_packets > 0:
                app_pct = (
                    count / total_app_packets
                ) * 100
            else:
                app_pct = 0.0

            bar = make_bar(count, max_app_count)

            print(
                f"   {rank:<3} "
                f"{app_name:<14} "
                f"{bar} "
                f"{count:<6} "
                f"{app_pct:5.1f}%"
            )

    print("═" * 56)

    # =========================================================
    # BLOCK 8 — GEO INTELLIGENCE (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   🌍  GEO INTELLIGENCE")
    print("═" * 56)

    print(
        f"   Internal Connections : "
        f"{geo_data['internal']}"
    )

    print(
        f"   External Connections : "
        f"{geo_data['external']}"
    )

    print()
    print("   Top External Hosts:")

    if top_external:

        for rank, (ip, count) in enumerate(
            top_external, start=1
        ):

            print(
                f"   {rank:<3} {ip:<18} {count} pkts"
            )

    else:

        print("   ⏳  No external traffic yet.")

    print("═" * 56)

    # =========================================================
    # BLOCK 9 — NETWORK INVENTORY (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   🖥  NETWORK INVENTORY")
    print("═" * 56)

    print(
        f"   Known Hosts : "
        f"{len(inventory_snapshot)}"
    )

    print()

    sorted_inventory = sorted(
        inventory_snapshot.items(),
        key=lambda x: x[1]["packets"],
        reverse=True
    )[:10]

    if sorted_inventory:

        for ip, data in sorted_inventory:

            first = datetime.fromtimestamp(
                data["first_seen"]
            ).strftime("%H:%M:%S")

            last = datetime.fromtimestamp(
                data["last_seen"]
            ).strftime("%H:%M:%S")

            print(
                f"   {ip:<18} "
                f"{data['packets']:<6} pkts  "
                f"first: {first}  "
                f"last: {last}"
            )

    else:

        print("   ⏳  No hosts discovered yet.")

    print("═" * 56)

    # =========================================================
    # BLOCK 10 — THREAT INTELLIGENCE DASHBOARD
    # =========================================================

    print("═" * 56)
    print("   🛡  THREAT INTELLIGENCE DASHBOARD")
    print("═" * 56)

    print(
        f"   Threat Score     : "
        f"{threat_score}/100"
    )

    print(
        f"   Risk Level       : {risk_level}"
    )

    print(
        f"   Security Health  : "
        f"{security_health}%"
    )

    print(
        f"   Active Threats   : "
        f"{len(active_alerts)}"
    )

    print("═" * 56)

    # =========================================================
    # BLOCK 11 — TOP THREATS
    # =========================================================

    print("═" * 56)
    print("   🔥  TOP THREATS")
    print("═" * 56)

    if active_alerts:

        for alert in active_alerts:

            print(f"   {alert}")

    else:

        print("   ✅ No active threats")

    print("═" * 56)

    # =========================================================
    # BLOCK 12 — ATTACK CLASSIFICATION (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   🎯  ATTACK CLASSIFICATION")
    print("═" * 56)

    if attack_categories:

        for category, cat_alerts in (
            attack_categories.items()
        ):

            print(
                f"   [{category}]"
            )

            for alert in cat_alerts:

                print(f"      {alert}")

            print()

    else:

        print("   ✅ No attacks classified")

    print("═" * 56)

    # =========================================================
    # BLOCK 13 — ANOMALY DETECTION ENGINE
    # =========================================================

    print("═" * 56)
    print("   🚨  ANOMALY DETECTION ENGINE")
    print("═" * 56)

    if active_alerts:

        for alert in active_alerts:

            print(f"   {alert}")

    else:

        print("   ✅ No anomalies detected")

    # =========================================================
    # BLOCK 14 — ALERT HISTORY
    # =========================================================

    print("═" * 56)
    print("   📜  RECENT ALERT HISTORY")
    print("═" * 56)

    if alerts:

        recent = alerts[-5:]

        for entry in recent:

            print(f"   {entry}")

    else:

        print("   No alerts generated yet")

    print("═" * 56)

    # =========================================================
    # BLOCK 15 — PERFORMANCE METRICS (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   ⚡  PERFORMANCE METRICS")
    print("═" * 56)

    print(
        f"   Uptime           : "
        f"{format_uptime(uptime)}"
    )

    print(
        f"   Packets Captured : {total}"
    )

    print(
        f"   Packets/sec      : "
        f"{packets_per_sec:.1f}"
    )

    print(
        f"   Sessions Tracked : "
        f"{session_count}"
    )

    print(
        f"   Known Hosts      : "
        f"{len(inventory_snapshot)}"
    )

    print("═" * 56)

    # =========================================================
    # BLOCK 16 — EXECUTIVE SECURITY SUMMARY (PHASE 11)
    # =========================================================

    print("═" * 56)
    print("   🏢  EXECUTIVE SECURITY SUMMARY")
    print("═" * 56)

    print(
        f"   Threat Score     : "
        f"{threat_score}/100"
    )

    print(
        f"   Risk Level       : {risk_level}"
    )

    print(
        f"   Security Health  : "
        f"{security_health}%"
    )

    print(
        f"   Total Hosts      : "
        f"{len(inventory_snapshot)}"
    )

    print(
        f"   Total Sessions   : "
        f"{session_count}"
    )

    print(
        f"   Total Alerts     : {len(alerts)}"
    )

    # Top Threat
    if active_alerts:

        print(
            f"   Top Threat       : "
            f"{active_alerts[0]}"
        )

    else:

        print(
            "   Top Threat       : None"
        )

    # Most Active Application
    if top_apps:

        print(
            f"   Top Application  : "
            f"{top_apps[0][0]}"
        )

    else:

        print(
            "   Top Application  : N/A"
        )

    print("═" * 56)

    if total == 0:

        print(
            "   ⏳ No IP packets captured yet"
        )

        print("═" * 56)


# =============================================================
#   FUNCTION: start_sniffing()
# =============================================================

def start_sniffing():

    sniff(
        prn=analyze_packet,
        store=False,
        count=0
    )


# =============================================================
#   MAIN PROGRAM
# =============================================================

if __name__ == "__main__":

    sniffer_thread = threading.Thread(

        target=start_sniffing,

        daemon=True,

        name="PacketSniffer"

    )

    sniffer_thread.start()


    # =============================================================
    #   STARTUP BANNER
    # =============================================================

    print("\n" + "═" * 56)

    print(
        "   🚀  NetScope AI — Ultimate Edition"
    )

    print(
        "   📡  Packet sniffer running"
    )

    print(
        "   🏆  Top Talkers enabled"
    )

    print(
        "   🚪  Port Analysis enabled"
    )

    print(
        "   📊  Bandwidth Monitor enabled"
    )

    print(
        "   🚨  Anomaly Detection enabled"
    )

    print(
        "   🔗  Session Intelligence enabled"
    )

    print(
        "   🧠  Application Intelligence enabled"
    )

    print(
        "   🛡  Threat Intelligence enabled"
    )

    print(
        "   🌍  Geo Intelligence enabled"
    )

    print(
        "   📝  Traffic Logging enabled"
    )

    print(
        "   🖥  Network Inventory enabled"
    )

    print(
        "   🏢  Executive Dashboard enabled"
    )

    print(
        "   🔄  Stats refresh every 5 seconds"
    )

    print(
        "   ⏹   Press Ctrl+C to stop"
    )

    print("═" * 56)


    # =============================================================
    #   MAIN LOOP
    # =============================================================

    try:

        while True:

            time.sleep(5)

            print_stats()


    # =============================================================
    #   CTRL+C SHUTDOWN
    # =============================================================

    except KeyboardInterrupt:

        print("\n")

        print(
            "   🛑  Ctrl+C detected"
        )

        print(
            "   📊  Printing final snapshot...\n"
        )

        print_stats()

        # =========================================================
        # GENERATE FINAL REPORT
        # =========================================================

        print("\n")
        print(
            "   📄  Generating final report..."
        )

        with lock:

            r_total = counters["total"]
            r_tcp = counters["tcp"]
            r_udp = counters["udp"]
            r_icmp = counters["icmp"]
            r_other = counters["other"]

            r_top_ips = ip_tracker.most_common(10)
            r_top_ports = port_tracker.most_common(10)
            r_top_apps = app_tracker.most_common(10)
            r_app_counts = dict(app_tracker)

            r_top_sessions = sorted(
                session_tracker.items(),
                key=lambda item: item[1]["packets"],
                reverse=True
            )[:10]

            r_geo_data = dict(geo_counters)

            r_inventory = {
                ip: dict(data)
                for ip, data
                in network_inventory.items()
            }

            r_suspicious = dict(suspicious_port_hits)

            r_scan = {
                ip: set(ports)
                for ip, ports
                in port_scan_tracker.items()
            }

            r_hosts = {
                ip: set(hosts)
                for ip, hosts
                in dst_host_tracker.items()
            }

        r_threat_score = calculate_threat_score(

            r_total, r_udp, r_icmp, 0,
            r_top_ips, r_app_counts,
            r_suspicious, r_scan, r_hosts

        )

        r_risk_level = get_risk_level(r_threat_score)

        r_security_health = 100 - r_threat_score

        r_active_alerts = detect_anomalies(

            r_total, r_udp, r_icmp, 0,
            r_top_ips, r_app_counts,
            r_suspicious, r_scan, r_hosts

        )

        report_path = generate_report(

            r_total, r_tcp, r_udp,
            r_icmp, r_other,
            r_top_ips, r_top_ports,
            r_top_apps, r_app_counts,
            r_threat_score, r_risk_level,
            r_security_health,
            r_active_alerts,
            r_top_sessions,
            r_geo_data, r_inventory

        )

        print(
            f"   ✅  Report saved: {report_path}"
        )

        # =========================================================
        # SHUTDOWN BANNER
        # =========================================================

        print("\n")
        print("═" * 56)

        print(
            "   ✅  NetScope AI — "
            "Ultimate Edition Complete"
        )

        print()

        print(
            "   🏢  Backend Engine Complete"
        )

        print()

        print(
            "   🎯  Ready For:"
        )

        print(
            "       → API Layer"
        )

        print(
            "       → Dashboard Backend"
        )

        print(
            "       → Frontend UI"
        )

        print(
            "       → Deployment"
        )

        print("═" * 56)

        print("\n")
