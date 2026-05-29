# =============================================================
#   NetScope AI — Phase 10: Threat Intelligence Engine
#   Project: Real-Time Network Traffic Analyzer
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
#
# =============================================================
#
#   NEW IN PHASE 10
#
#   ✅ Suspicious Port Database
#
#   ✅ Suspicious Port Detection
#
#   ✅ Port Scan Detection
#
#   ✅ Reconnaissance Activity Detection
#
#   ✅ Dynamic Threat Score (0–100)
#
#   ✅ Risk Level Classification
#
#   ✅ Threat Intelligence Dashboard
#
#   ✅ Top Threats Display
#
# =============================================================
#
#   WHAT IS THREAT INTELLIGENCE?
#
#   Threat intelligence transforms raw network data
#   into actionable security insights.
#
#   Instead of just detecting anomalies,
#   we now correlate multiple signals:
#
#       Suspicious ports
#              +
#       Scanning behavior
#              +
#       Reconnaissance patterns
#              +
#       Traffic anomalies
#              ↓
#       Unified Threat Score
#
# =============================================================
#
#   SUSPICIOUS PORTS
#
#   Certain port numbers are commonly associated
#   with malware, backdoors, RATs, and unauthorized
#   services:
#
#       4444   → Metasploit default
#       5555   → Android Debug Bridge
#       6666   → IRC backdoors
#       1337   → "leet" backdoors
#       31337  → Back Orifice
#       12345  → NetBus trojan
#
#   Any traffic on these ports generates an alert.
#
# =============================================================
#
#   PORT SCAN DETECTION
#
#   A port scan occurs when a single source IP
#   contacts many different destination ports
#   on the network.
#
#   Threshold: > 20 unique destination ports
#
#   This is a classic reconnaissance technique
#   used to discover open services.
#
# =============================================================
#
#   RECONNAISSANCE DETECTION
#
#   Reconnaissance combines:
#
#       High ICMP traffic (ping sweeps)
#              +
#       Many unique destination hosts
#
#   This pattern suggests an attacker is mapping
#   the network before launching an attack.
#
# =============================================================
#
#   THREAT SCORE
#
#   A dynamic score from 0 to 100 that aggregates
#   multiple threat signals:
#
#       Host Dominance     → +15
#       High ICMP          → +15
#       High UDP           → +15
#       Bandwidth Spike    → +20
#       Unknown Traffic    → +15
#       Suspicious Port    → +20
#       Port Scan          → +30
#       Recon Activity     → +30
#
#   Score capped at 100.
#
# =============================================================
#
#   RISK LEVELS
#
#       0–20   → LOW
#       21–40  → MEDIUM
#       41–70  → HIGH
#       71–100 → CRITICAL
#
# =============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP

import threading
import time

from datetime import datetime
from collections import Counter


# =============================================================
#   SECTION 1 — PROTOCOL COUNTERS
# =============================================================

counters = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
}


# =============================================================
#   SECTION 2 — TOP TALKER TRACKER
# =============================================================

ip_tracker = Counter()


# =============================================================
#   SECTION 3 — PORT TRACKER
# =============================================================

port_tracker = Counter()


# =============================================================
#   SECTION 4 — COMMON PORT DATABASE
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
#   SECTION 5 — BANDWIDTH TRACKER
# =============================================================

bandwidth = {

    "total_bytes": 0,

    "window_bytes": 0,

    "window_packets": 0,

    "window_start": time.time(),
}


# =============================================================
#   SECTION 6 — ANOMALY DETECTION ENGINE
# =============================================================
#
# alerts
# -------
#
# Stores recent alerts generated by detection rules.
#
# Example:
#
# [
#   "HIGH UDP TRAFFIC",
#   "HIGH ICMP TRAFFIC"
# ]
#
# =============================================================

alerts = []


MAX_ALERTS = 20


# =============================================================
#   DETECTION THRESHOLDS
# =============================================================

UDP_THRESHOLD = 70

ICMP_THRESHOLD = 20

BANDWIDTH_THRESHOLD = 500000

HOST_DOMINANCE_THRESHOLD = 80

UNKNOWN_APP_THRESHOLD = 30

PORT_SCAN_THRESHOLD = 20

RECON_ICMP_THRESHOLD = 15

RECON_HOSTS_THRESHOLD = 10


# =============================================================
#   SECTION 7 — SESSION TRACKER (PHASE 8)
# =============================================================
#
# A Session represents a communication flow:
#
#   Source IP
#   Destination IP
#   Protocol
#   Source Port
#   Destination Port
#
# =============================================================

session_tracker = {}


# =============================================================
#   SECTION 8 — APPLICATION INTELLIGENCE (PHASE 9)
# =============================================================
#
# Application Tracker
# --------------------
#
# Records application-level activity derived from
# observed TCP/UDP port numbers.
#
# =============================================================

app_tracker = Counter()


# =============================================================
#   APPLICATION PORT MAP
# =============================================================

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
#   SECTION 9 — SUSPICIOUS PORT DATABASE (PHASE 10)
# =============================================================
#
# Ports commonly associated with:
#
#   Malware
#   Backdoors
#   RATs (Remote Access Trojans)
#   Unauthorized services
#
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
#   SECTION 10 — PORT SCAN TRACKER (PHASE 10)
# =============================================================
#
# Tracks unique destination ports contacted
# by each source IP.
#
# Structure:
#
#   {
#       "192.168.1.60": {80, 443, 22, ...},
#       "10.0.0.5":     {53, 8080, ...}
#   }
#
# If a source IP contacts > 20 unique ports:
#
#   → Port scan alert
#
# =============================================================

port_scan_tracker = {}


# =============================================================
#   SECTION 11 — DESTINATION HOST TRACKER (PHASE 10)
# =============================================================
#
# Tracks unique destination IPs contacted
# by each source IP.
#
# Used for reconnaissance detection.
#
# Structure:
#
#   {
#       "192.168.1.60": {"10.0.0.1", "10.0.0.2", ...}
#   }
#
# =============================================================

dst_host_tracker = {}


# =============================================================
#   SECTION 12 — SUSPICIOUS PORT HIT TRACKER (PHASE 10)
# =============================================================
#
# Tracks whether suspicious port traffic has
# been observed during the session.
#
# =============================================================

suspicious_port_hits = Counter()


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
#
# Maps threat score to risk level string.
#
#   0–20   → LOW
#   21–40  → MEDIUM
#   41–70  → HIGH
#   71–100 → CRITICAL
#
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
#   SECTION 13 — THREAD LOCK
# =============================================================

lock = threading.Lock()


# =============================================================
#   FUNCTION: analyze_packet(packet)
# =============================================================
#
#   Called by Scapy for EVERY packet captured.
#
#   Responsibilities:
#
#       Phase 3  → Protocol Counters
#
#       Phase 4  → IP Tracking
#
#       Phase 5  → Port Tracking
#
#       Phase 6  → Bandwidth Tracking
#
#       Phase 7  → Supplies data used by
#                  anomaly detection
#
#       Phase 8  → Session Tracking
#
#       Phase 9  → Application Classification
#
#       Phase 10 → Suspicious Port Detection
#                  Port Scan Tracking
#                  Destination Host Tracking
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
        #
        # Check if either src_port or dst_port is
        # in the suspicious ports database.
        #
        # ======================================================

        if src_port in SUSPICIOUS_PORTS:

            suspicious_port_hits[src_port] += 1

        if dst_port in SUSPICIOUS_PORTS:

            suspicious_port_hits[dst_port] += 1

        # ======================================================
        # PHASE 10 — PORT SCAN TRACKING
        # ======================================================
        #
        # Track unique destination ports per source IP.
        #
        # Only for TCP/UDP packets (they have ports).
        #
        # ======================================================

        if packet.haslayer(TCP) or packet.haslayer(UDP):

            if src_ip not in port_scan_tracker:

                port_scan_tracker[src_ip] = set()

            port_scan_tracker[src_ip].add(dst_port)

        # ======================================================
        # PHASE 10 — DESTINATION HOST TRACKING
        # ======================================================
        #
        # Track unique destination IPs per source IP.
        #
        # Used for reconnaissance detection.
        #
        # ======================================================

        if src_ip not in dst_host_tracker:

            dst_host_tracker[src_ip] = set()

        dst_host_tracker[src_ip].add(dst_ip)


# =============================================================
#   FUNCTION: format_bytes()
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
#   FUNCTION: make_bar()
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


# =============================================================
#   FUNCTION: detect_anomalies()
# =============================================================
#
#   Phase 7 Core Engine
#   + Phase 9 Extension
#   + Phase 10 Threat Intelligence
#
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
    # RULE 1
    # HIGH UDP TRAFFIC
    # =========================================================

    if total > 0:

        udp_pct = (
            udp / total
        ) * 100

        if udp_pct > UDP_THRESHOLD:

            message = (
                "HIGH UDP TRAFFIC DETECTED"
            )

            current_alerts.append(
                f"⚠ {message}"
            )

    # =========================================================
    # RULE 2
    # HIGH ICMP TRAFFIC
    # =========================================================

    if total > 0:

        icmp_pct = (
            icmp / total
        ) * 100

        if icmp_pct > ICMP_THRESHOLD:

            message = (
                "HIGH ICMP TRAFFIC DETECTED"
            )

            current_alerts.append(
                f"⚠ {message}"
            )

    # =========================================================
    # RULE 3
    # BANDWIDTH SPIKE
    # =========================================================

    if bytes_per_sec > BANDWIDTH_THRESHOLD:

        message = (
            "BANDWIDTH SPIKE DETECTED"
        )

        current_alerts.append(
            f"⚠ {message}"
        )

    # =========================================================
    # RULE 4
    # HOST DOMINANCE
    # =========================================================

    if top_ips and total > 0:

        top_ip_count = top_ips[0][1]

        host_pct = (
            top_ip_count / total
        ) * 100

        if host_pct > HOST_DOMINANCE_THRESHOLD:

            message = (
                "HOST DOMINANCE DETECTED"
            )

            current_alerts.append(
                f"⚠ {message}"
            )

    # =========================================================
    # RULE 5 (PHASE 9)
    # EXCESSIVE UNKNOWN TRAFFIC
    # =========================================================

    total_app_packets = sum(app_counts.values())

    if total_app_packets > 0:

        other_count = app_counts.get("OTHER", 0)

        other_pct = (
            other_count / total_app_packets
        ) * 100

        if other_pct > UNKNOWN_APP_THRESHOLD:

            message = (
                "EXCESSIVE UNKNOWN TRAFFIC DETECTED"
            )

            current_alerts.append(
                f"⚠ {message}"
            )

    # =========================================================
    # RULE 6 (PHASE 10)
    # SUSPICIOUS PORT DETECTION
    # =========================================================
    #
    # If ANY traffic has been observed on a
    # suspicious port, generate an alert.
    #
    # =========================================================

    if sum(suspicious_hits.values()) > 0:

        message = (
            "SUSPICIOUS PORT DETECTED"
        )

        current_alerts.append(
            f"⚠ {message}"
        )

    # =========================================================
    # RULE 7 (PHASE 10)
    # PORT SCAN DETECTION
    # =========================================================
    #
    # If any source IP has contacted > 20 unique
    # destination ports.
    #
    # =========================================================

    for src_ip, ports in scan_data.items():

        if len(ports) > PORT_SCAN_THRESHOLD:

            message = (
                "POSSIBLE PORT SCAN DETECTED"
            )

            current_alerts.append(
                f"⚠ {message}"
            )

            break

    # =========================================================
    # RULE 8 (PHASE 10)
    # RECONNAISSANCE DETECTION
    # =========================================================
    #
    # Triggered when:
    #
    #   ICMP > RECON_ICMP_THRESHOLD (15%)
    #
    #   AND
    #
    #   Any source IP has contacted >
    #   RECON_HOSTS_THRESHOLD (10) unique hosts
    #
    # =========================================================

    recon_detected = False

    if total > 0:

        icmp_pct = (
            icmp / total
        ) * 100

        if icmp_pct > RECON_ICMP_THRESHOLD:

            for src_ip, hosts in host_data.items():

                if len(hosts) > RECON_HOSTS_THRESHOLD:

                    recon_detected = True

                    break

    if recon_detected:

        message = (
            "RECONNAISSANCE ACTIVITY DETECTED"
        )

        current_alerts.append(
            f"⚠ {message}"
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
#
#   Computes a dynamic threat score from 0 to 100
#   based on all active threat signals.
#
#   Scoring Rules:
#
#       Host Dominance     → +15
#       High ICMP          → +15
#       High UDP           → +15
#       Bandwidth Spike    → +20
#       Unknown Traffic    → +15
#       Suspicious Port    → +20
#       Port Scan          → +30
#       Recon Activity     → +30
#
#   Score is capped at 100.
#
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

    # =========================================================
    # HOST DOMINANCE → +15
    # =========================================================

    if top_ips and total > 0:

        top_ip_count = top_ips[0][1]

        host_pct = (
            top_ip_count / total
        ) * 100

        if host_pct > HOST_DOMINANCE_THRESHOLD:

            score += 15

    # =========================================================
    # HIGH ICMP → +15
    # =========================================================

    if total > 0:

        icmp_pct = (
            icmp / total
        ) * 100

        if icmp_pct > ICMP_THRESHOLD:

            score += 15

    # =========================================================
    # HIGH UDP → +15
    # =========================================================

    if total > 0:

        udp_pct = (
            udp / total
        ) * 100

        if udp_pct > UDP_THRESHOLD:

            score += 15

    # =========================================================
    # BANDWIDTH SPIKE → +20
    # =========================================================

    if bytes_per_sec > BANDWIDTH_THRESHOLD:

        score += 20

    # =========================================================
    # UNKNOWN TRAFFIC → +15
    # =========================================================

    total_app_packets = sum(app_counts.values())

    if total_app_packets > 0:

        other_count = app_counts.get("OTHER", 0)

        other_pct = (
            other_count / total_app_packets
        ) * 100

        if other_pct > UNKNOWN_APP_THRESHOLD:

            score += 15

    # =========================================================
    # SUSPICIOUS PORT → +20
    # =========================================================

    if sum(suspicious_hits.values()) > 0:

        score += 20

    # =========================================================
    # PORT SCAN → +30
    # =========================================================

    for src_ip, ports in scan_data.items():

        if len(ports) > PORT_SCAN_THRESHOLD:

            score += 30

            break

    # =========================================================
    # RECON ACTIVITY → +30
    # =========================================================

    if total > 0:

        icmp_pct = (
            icmp / total
        ) * 100

        if icmp_pct > RECON_ICMP_THRESHOLD:

            for src_ip, hosts in host_data.items():

                if len(hosts) > RECON_HOSTS_THRESHOLD:

                    score += 30

                    break

    # =========================================================
    # CAP AT 100
    # =========================================================

    if score > 100:

        score = 100

    return score


# =============================================================
#   FUNCTION: print_stats()
# =============================================================
#
#   Central Reporting Engine
#
#   Displays:
#
#       Block 1  → Protocol Statistics
#
#       Block 2  → Top Active IPs
#
#       Block 3  → Top Ports
#
#       Block 4  → Bandwidth Monitor
#
#       Block 5  → Top Active Sessions
#
#       Block 6  → Application Intelligence
#
#       Block 7  → Threat Intelligence Dashboard
#
#       Block 8  → Top Threats
#
#       Block 9  → Anomaly Detection Engine
#
#       Block 10 → Alert History
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

        # ======================================================
        # PHASE 8 — TOP SESSION SNAPSHOT
        # ======================================================

        top_sessions = sorted(

            session_tracker.items(),

            key=lambda item:
                item[1]["packets"],

            reverse=True

        )[:5]

        # ======================================================
        # PHASE 9 — APPLICATION SNAPSHOT
        # ======================================================

        app_counts = dict(app_tracker)

        top_apps = app_tracker.most_common(10)

        # ======================================================
        # PHASE 10 — THREAT DATA SNAPSHOT
        # ======================================================

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

        bytes_per_sec = (
            window_bytes / elapsed
        )

        packets_per_sec = (
            window_packets / elapsed
        )

    else:

        bytes_per_sec = 0

        packets_per_sec = 0

    # =========================================================
    # ANOMALY DETECTION
    # =========================================================

    active_alerts = detect_anomalies(

        total,

        udp,

        icmp,

        bytes_per_sec,

        top_ips,

        app_counts,

        suspicious_hits,

        scan_data,

        host_data

    )

    # =========================================================
    # THREAT SCORE CALCULATION
    # =========================================================

    threat_score = calculate_threat_score(

        total,

        udp,

        icmp,

        bytes_per_sec,

        top_ips,

        app_counts,

        suspicious_hits,

        scan_data,

        host_data

    )

    risk_level = get_risk_level(threat_score)

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )

    def pct(value):

        return (
            value / total * 100
        ) if total > 0 else 0.0

    # =========================================================
    # BLOCK 1
    # PROTOCOL STATISTICS
    # =========================================================

    print("\n" + "═" * 44)

    print(
        "   📊  NETSCOPE AI — LIVE STATISTICS"
    )

    print(
        f"   🕐  Snapshot at : {timestamp}"
    )

    print("═" * 44)

    print(
        f"   Total Packets  : {total}"
    )

    print(
        f"   TCP  Packets   : {tcp:<6} ({pct(tcp):.1f}%)"
    )

    print(
        f"   UDP  Packets   : {udp:<6} ({pct(udp):.1f}%)"
    )

    print(
        f"   ICMP Packets   : {icmp:<6} ({pct(icmp):.1f}%)"
    )

    print(
        f"   Other Packets  : {other:<6} ({pct(other):.1f}%)"
    )

    # =========================================================
    # BLOCK 2
    # TOP TALKERS
    # =========================================================

    print("═" * 44)

    print(
        "   🏆  TOP 10 ACTIVE IP ADDRESSES"
    )

    print("═" * 44)

    if not top_ips:

        print(
            "   ⏳  Waiting for IP traffic..."
        )

    else:

        max_ip_count = top_ips[0][1]

        for rank, (ip, count) in enumerate(
            top_ips,
            start=1
        ):

            bar = make_bar(
                count,
                max_ip_count
            )

            print(
                f"   {rank:<3} "
                f"{ip:<18} "
                f"{bar} "
                f"{count}"
            )

    # =========================================================
    # BLOCK 3
    # TOP PORTS
    # =========================================================

    print("═" * 44)

    print(
        "   🚪  TOP 10 PORTS"
    )

    print("═" * 44)

    if not top_ports:

        print(
            "   ⏳ Waiting for TCP/UDP traffic..."
        )

    else:

        max_port_count = top_ports[0][1]

        for rank, (port, count) in enumerate(
            top_ports,
            start=1
        ):

            service = COMMON_PORTS.get(
                port,
                "UNKNOWN"
            )

            bar = make_bar(
                count,
                max_port_count
            )

            print(
                f"   {rank:<3} "
                f"{port:<6} "
                f"{service:<12} "
                f"{bar} "
                f"{count}"
            )

    # =========================================================
    # BLOCK 4
    # BANDWIDTH MONITOR
    # =========================================================

    print("═" * 44)

    print(
        "   📡  BANDWIDTH MONITOR"
    )

    print("═" * 44)

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

    # ==========================================================
    # BLOCK 5
    # TOP ACTIVE SESSIONS (PHASE 8)
    # ==========================================================

    print("═" * 44)
    print("   🔗  TOP ACTIVE SESSIONS")
    print("═" * 44)

    if not top_sessions:

        print("   ⏳  No active sessions yet.")

    else:

        for session_key, data in top_sessions:

            (
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port
            ) = session_key

            duration = (
                data["last_seen"]
                -
                data["first_seen"]
            )

            print()

            print(
                f"   {src_ip}"
            )

            print(
                f"      → {dst_ip}"
            )

            print()

            print(
                f"   {protocol}"
            )

            print(
                f"   {src_port} → {dst_port}"
            )

            print()

            print(
                f"   Packets  : "
                f"{data['packets']}"
            )

            print(
                f"   Bytes    : "
                f"{format_bytes(data['bytes'])}"
            )

            print(
                f"   Duration : "
                f"{duration:.1f} sec"
            )

            print()

            print(
                "   " + "─" * 32
            )

    print("═" * 44)

    # ==========================================================
    # BLOCK 6
    # APPLICATION INTELLIGENCE (PHASE 9)
    # ==========================================================

    print("═" * 44)

    print(
        "   🧠  APPLICATION INTELLIGENCE"
    )

    print("═" * 44)

    total_app_packets = sum(
        app_counts.values()
    )

    if not top_apps:

        print(
            "   ⏳  Waiting for application traffic..."
        )

    else:

        max_app_count = top_apps[0][1]

        for rank, (app_name, count) in enumerate(
            top_apps,
            start=1
        ):

            if total_app_packets > 0:

                app_pct = (
                    count / total_app_packets
                ) * 100

            else:

                app_pct = 0.0

            bar = make_bar(
                count,
                max_app_count
            )

            print(
                f"   {rank:<3} "
                f"{app_name:<14} "
                f"{bar} "
                f"{count:<6} "
                f"{app_pct:5.1f}%"
            )

    print("═" * 44)

    # ==========================================================
    # BLOCK 7
    # THREAT INTELLIGENCE DASHBOARD (PHASE 10)
    # ==========================================================

    print("═" * 44)

    print(
        "   🛡  THREAT INTELLIGENCE DASHBOARD"
    )

    print("═" * 44)

    print(
        f"   Threat Score    : "
        f"{threat_score}/100"
    )

    print(
        f"   Risk Level      : "
        f"{risk_level}"
    )

    print(
        f"   Active Threats  : "
        f"{len(active_alerts)}"
    )

    print("═" * 44)

    # ==========================================================
    # BLOCK 8
    # TOP THREATS (PHASE 10)
    # ==========================================================

    print("═" * 44)

    print(
        "   🔥  TOP THREATS"
    )

    print("═" * 44)

    if active_alerts:

        for alert in active_alerts:

            print(
                f"   {alert}"
            )

    else:

        print(
            "   ✅ No active threats"
        )

    print("═" * 44)

    # =========================================================
    # BLOCK 9
    # ANOMALY DETECTION ENGINE
    # =========================================================

    print("═" * 44)

    print(
        "   🚨  ANOMALY DETECTION ENGINE"
    )

    print("═" * 44)

    if active_alerts:

        for alert in active_alerts:

            print(
                f"   {alert}"
            )

    else:

        print(
            "   ✅ No anomalies detected"
        )

    # =========================================================
    # BLOCK 10
    # ALERT HISTORY
    # =========================================================

    print("═" * 44)

    print(
        "   📜  RECENT ALERT HISTORY"
    )

    print("═" * 44)

    if alerts:

        recent = alerts[-5:]

        for entry in recent:

            print(
                f"   {entry}"
            )

    else:

        print(
            "   No alerts generated yet"
        )

    print("═" * 44)

    if total == 0:

        print(
            "   ⏳ No IP packets captured yet"
        )

        print("═" * 44)


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
#
#   Architecture:
#
#       Thread 1
#       --------
#       Packet Sniffer
#
#       Thread 2
#       --------
#       Statistics Engine
#
# =============================================================

sniffer_thread = threading.Thread(

    target=start_sniffing,

    daemon=True,

    name="PacketSniffer"

)

sniffer_thread.start()


# =============================================================
#   STARTUP BANNER
# =============================================================

print("\n" + "═" * 44)

print(
    "   🚀  NetScope AI — Phase 10 Active"
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
    "   🔄  Stats refresh every 5 seconds"
)

print(
    "   ⏹   Press Ctrl+C to stop"
)

print("═" * 44)


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

    print("\n")

    print(
        "   ✅  NetScope AI Phase 10 complete"
    )

    print(
        "   🛡  Threat Intelligence Engine Active"
    )

    print(
        "   🎯  Ready for Phase 11!"
    )

    print("\n")
