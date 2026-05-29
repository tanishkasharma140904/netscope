# =============================================================
#   NetScope AI — Phase 5: Port Analysis
# =============================================================
#
#   Builds on:
#
#   Phase 1 → Packet Detection
#   Phase 2 → Packet Inspection
#   Phase 3 → Traffic Statistics
#   Phase 4 → Top Talker Analysis
#
#   NEW IN PHASE 5:
#
#   ✅ Source Port Detection
#   ✅ Destination Port Detection
#   ✅ Port Usage Tracking
#   ✅ Service Identification
#   ✅ Top 10 Active Ports
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
#   SECTION 2 — IP TRACKER (PHASE 4)
# =============================================================

ip_tracker = Counter()


# =============================================================
#   SECTION 3 — PORT TRACKER (PHASE 5)
# =============================================================
#
# Key:
#     Port Number
#
# Value:
#     Packet Count
#
# Example:
#
#     443 → 5000
#     53  → 2000
#     80  → 500
#
# =============================================================

port_tracker = Counter()


# =============================================================
#   SECTION 4 — COMMON PORT DATABASE
# =============================================================
#
# Used to convert:
#
#     443 → HTTPS
#     53  → DNS
#
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
#   SECTION 5 — THREAD LOCK
# =============================================================

lock = threading.Lock()


# =============================================================
#   FUNCTION: analyze_packet()
# =============================================================
#
# Called for every packet captured by Scapy.
#
# Responsibilities:
#
#   1. Update protocol counters
#   2. Update IP tracker
#   3. Update port tracker
#
# =============================================================

def analyze_packet(packet):

    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    with lock:

        # ==========================================
        # PROTOCOL ANALYSIS
        # ==========================================

        counters["total"] += 1

        if packet.haslayer(TCP):
            counters["tcp"] += 1

        elif packet.haslayer(UDP):
            counters["udp"] += 1

        elif packet.haslayer(ICMP):
            counters["icmp"] += 1

        else:
            counters["other"] += 1

        # ==========================================
        # PHASE 4 — TOP IP TRACKER
        # ==========================================

        ip_tracker[src_ip] += 1
        ip_tracker[dst_ip] += 1

        # ==========================================
        # PHASE 5 — PORT ANALYSIS
        # ==========================================

        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            port_tracker[src_port] += 1
            port_tracker[dst_port] += 1

        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            src_port = udp_layer.sport
            dst_port = udp_layer.dport

            port_tracker[src_port] += 1
            port_tracker[dst_port] += 1


# =============================================================
#   HELPER FUNCTION
# =============================================================

def make_bar(count, max_count, bar_width=20):

    if max_count == 0:
        return " " * bar_width

    filled = int((count / max_count) * bar_width)

    empty = bar_width - filled

    return "█" * filled + "░" * empty
    # =============================================================
#   FUNCTION: print_stats()
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

    timestamp = datetime.now().strftime("%H:%M:%S")

    def pct(value):
        return (value / total * 100) if total > 0 else 0.0

    print("\n" + "═" * 44)

    print("   📊  NETSCOPE AI — LIVE STATISTICS")
    print(f"   🕐  Snapshot at : {timestamp}")

    print("═" * 44)

    print(f"   Total Packets  : {total}")

    print(f"   TCP  Packets   : {tcp:<6}  ({pct(tcp):.1f}%)")
    print(f"   UDP  Packets   : {udp:<6}  ({pct(udp):.1f}%)")
    print(f"   ICMP Packets   : {icmp:<6}  ({pct(icmp):.1f}%)")
    print(f"   Other Packets  : {other:<6}  ({pct(other):.1f}%)")

    # =========================================================
    # TOP ACTIVE IP ADDRESSES
    # =========================================================

    print("═" * 44)
    print("   🏆  TOP 10 ACTIVE IP ADDRESSES")
    print("═" * 44)

    if not top_ips:

        print("   ⏳  Waiting for IP traffic...")

    else:

        max_ip_count = top_ips[0][1]

        for rank, (ip, count) in enumerate(top_ips, start=1):

            bar = make_bar(count, max_ip_count)

            print(
                f"   {rank:<3} {ip:<18} {bar}  {count}"
            )

    # =========================================================
    # TOP PORTS
    # =========================================================

    print("═" * 44)
    print("   🚪  TOP 10 PORTS")
    print("═" * 44)

    if not top_ports:

        print("   ⏳  Waiting for TCP/UDP traffic...")

    else:

        max_port_count = top_ports[0][1]

        for rank, (port, count) in enumerate(top_ports, start=1):

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

    print("═" * 44)

    if total == 0:

        print("   ⏳  No IP packets captured yet.")
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

sniffer_thread = threading.Thread(
    target=start_sniffing,
    daemon=True,
    name="PacketSniffer"
)

sniffer_thread.start()


print("\n" + "═" * 44)
print("   🚀  NetScope AI — Phase 5 Active")
print("   📡  Packet sniffer running")
print("   🏆  Top Talkers enabled")
print("   🚪  Port Analysis enabled")
print("   📊  Refresh every 5 seconds")
print("   ⏹   Press Ctrl+C to stop")
print("═" * 44)


try:

    while True:

        time.sleep(5)

        print_stats()

except KeyboardInterrupt:

    print("\n")
    print("   🛑  Ctrl+C detected")
    print("   📊  Printing final snapshot...\n")

    print_stats()

    print("\n")
    print("   ✅  NetScope AI Phase 5 complete")
    print("   🎯  Ready for Phase 6: Bandwidth Monitor")
    print("\n")