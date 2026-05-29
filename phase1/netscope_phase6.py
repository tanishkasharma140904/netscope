# =============================================================
#   NetScope AI — Phase 6: Bandwidth Monitor
#   Project: Real-Time Network Traffic Analyzer
# =============================================================
#
#   Builds on:
#
#   Phase 1 → Packet Detection
#   Phase 2 → Packet Inspection
#   Phase 3 → Traffic Statistics
#   Phase 4 → Top Talker Analysis
#   Phase 5 → Port Analysis
#
#   NEW IN PHASE 6:
#
#   ✅ Packet Size Measurement   (len(packet))
#   ✅ Total Bytes Transferred   (cumulative, never resets)
#   ✅ Bytes Per Second          (windowed throughput)
#   ✅ Packets Per Second        (windowed rate)
#   ✅ Auto Unit Conversion      (B / KB / MB / GB)
#   ✅ Live Bandwidth Monitor    (displayed every 5 seconds)
#
# =============================================================
#
#   📘  KEY CONCEPTS EXPLAINED
#
#   ┌─────────────────────────────────────────────────────────┐
#   │  BANDWIDTH vs THROUGHPUT                                │
#   │                                                         │
#   │  Bandwidth  → The MAXIMUM data a link can carry.       │
#   │               Set by your hardware or ISP contract.    │
#   │               Example: "I have a 100 Mbps connection." │
#   │               Like the total width of a highway.       │
#   │                                                         │
#   │  Throughput → The ACTUAL data flowing right now.       │
#   │               Measured in real time from real packets.  │
#   │               Example: "I'm using 34 Mbps right now."  │
#   │               Like the cars actually on the road.      │
#   │                                                         │
#   │  NetScope measures THROUGHPUT — what's really there.   │
#   └─────────────────────────────────────────────────────────┘
#
#   ┌─────────────────────────────────────────────────────────┐
#   │  BYTES vs PACKETS                                       │
#   │                                                         │
#   │  Packet → One individual unit of data on the network.  │
#   │           Like an envelope in the postal system.       │
#   │                                                         │
#   │  Byte   → The amount of data inside that envelope.     │
#   │           A packet can carry 1 byte or 65,000+ bytes.  │
#   │                                                         │
#   │  Packets/sec → HOW MANY messages are arriving.         │
#   │  Bytes/sec   → HOW MUCH data is arriving.              │
#   │                                                         │
#   │  High pkt/s + low B/s → many tiny packets             │
#   │                          (DNS queries, VoIP, gaming)   │
#   │                                                         │
#   │  Low  pkt/s + high B/s → few large packets            │
#   │                          (file transfers, video)       │
#   └─────────────────────────────────────────────────────────┘
#
#   ┌─────────────────────────────────────────────────────────┐
#   │  NETWORK UTILIZATION                                    │
#   │                                                         │
#   │  Utilization = (Throughput / Bandwidth) × 100%         │
#   │                                                         │
#   │  If your link is 100 Mbps and throughput is 34 Mbps:   │
#   │    Utilization = 34%                                    │
#   │                                                         │
#   │  NetScope shows raw throughput numbers because it      │
#   │  cannot automatically know your link's max bandwidth.  │
#   │  Compare Bytes/sec against your plan's speed to get    │
#   │  a rough utilization estimate yourself.                │
#   └─────────────────────────────────────────────────────────┘
#
#   ┌─────────────────────────────────────────────────────────┐
#   │  WINDOWED MEASUREMENT (How per-second rates work)       │
#   │                                                         │
#   │  Every 5 seconds NetScope:                             │
#   │    1. Records bytes + packets seen in those 5 seconds   │
#   │    2. Divides by elapsed time → per-second rate        │
#   │    3. Resets the window counters to zero               │
#   │    4. Starts a fresh count for the next 5-second window│
#   │                                                         │
#   │  This produces a rolling "current speed" reading,      │
#   │  exactly like a car's speedometer showing right now,   │
#   │  not your average speed for the whole trip.            │
#   └─────────────────────────────────────────────────────────┘
#
# =============================================================

# scapy.all   → Packet capture and protocol layer detection
# threading   → Run sniffer and reporter simultaneously
# time        → 5-second sleep interval + window timing
# datetime    → Timestamp each statistics snapshot
# collections → Counter: a dictionary built for counting things
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from datetime import datetime
from collections import Counter


# =============================================================
#   SECTION 1 — PROTOCOL COUNTERS (Phase 3)
# =============================================================
#   Simple integer counters stored in a dictionary.
#   Updated every time a matching packet arrives.
# =============================================================
counters = {
    "total" : 0,
    "tcp"   : 0,
    "udp"   : 0,
    "icmp"  : 0,
    "other" : 0,
}


# =============================================================
#   SECTION 2 — IP TRACKER (Phase 4)
# =============================================================
#   collections.Counter maps each IP address to the number of
#   times it appeared as source OR destination.
#   most_common(10) returns the top 10 entries instantly.
# =============================================================
ip_tracker = Counter()


# =============================================================
#   SECTION 3 — PORT TRACKER (Phase 5)
# =============================================================
#   Same Counter pattern, but keyed on port numbers.
#   Both source and destination ports are counted.
#
#   Example after a few minutes of traffic:
#     443 → 5000   (HTTPS)
#     53  → 2000   (DNS)
#     80  → 500    (HTTP)
# =============================================================
port_tracker = Counter()


# =============================================================
#   SECTION 4 — COMMON PORT DATABASE (Phase 5)
# =============================================================
#   Maps port numbers to human-readable service names.
#   Used to convert 443 → "HTTPS", 53 → "DNS", etc.
# =============================================================
COMMON_PORTS = {
    20   : "FTP-DATA",
    21   : "FTP",
    22   : "SSH",
    23   : "TELNET",
    25   : "SMTP",
    53   : "DNS",
    67   : "DHCP",
    68   : "DHCP",
    80   : "HTTP",
    110  : "POP3",
    123  : "NTP",
    143  : "IMAP",
    161  : "SNMP",
    443  : "HTTPS",
    465  : "SMTPS",
    587  : "SMTP",
    993  : "IMAPS",
    995  : "POP3S",
    3306 : "MYSQL",
    3389 : "RDP",
    5432 : "POSTGRESQL",
    6379 : "REDIS",
    8080 : "HTTP-ALT",
}


# =============================================================
#   SECTION 5 — BANDWIDTH TRACKER (NEW IN PHASE 6)
# =============================================================
#
#   Four values work together to produce speed readings:
#
#   total_bytes    → Grand total of bytes seen since startup.
#                    Never resets. Shows cumulative data volume.
#
#   window_bytes   → Bytes seen only in the CURRENT 5-sec window.
#                    Resets to 0 after every snapshot.
#                    Dividing by elapsed seconds gives bytes/sec.
#
#   window_packets → Packets seen only in the CURRENT 5-sec window.
#                    Resets to 0 after every snapshot.
#                    Dividing by elapsed seconds gives pkts/sec.
#
#   window_start   → The Unix timestamp when the current window
#                    began. time.time() returns a float of seconds
#                    since 1 Jan 1970. Subtracting from "now" gives
#                    elapsed seconds for an exact speed calculation.
#
#   Why measure the window exactly rather than assuming 5.0 sec?
#   Because sleep(5) is never perfectly 5.000 seconds — the OS
#   scheduler adds tiny delays. Measuring elapsed time directly
#   prevents drift from accumulating over long sessions.
#
# =============================================================
bandwidth = {
    "total_bytes"    : 0,
    "window_bytes"   : 0,
    "window_packets" : 0,
    "window_start"   : time.time(),   # snapshot time.time() at startup
}


# =============================================================
#   SECTION 6 — THREAD LOCK
# =============================================================
#   One lock protects ALL shared data structures:
#     - counters
#     - ip_tracker
#     - port_tracker
#     - bandwidth
#
#   Only one thread may read or write shared data at a time.
#   This prevents race conditions (torn reads/writes).
# =============================================================
lock = threading.Lock()


# =============================================================
#   FUNCTION: analyze_packet(packet)
# =============================================================
#   Called by Scapy for every captured packet.
#
#   Responsibilities (one new step added in Phase 6):
#
#     1. Skip non-IP packets
#     2. Update protocol counters    (Phase 3)
#     3. Update IP tracker           (Phase 4)
#     4. Update port tracker         (Phase 5)
#     5. Update bandwidth tracker    (Phase 6 — NEW)
# =============================================================
def analyze_packet(packet):

    # Skip anything without an IP layer (ARP, raw Ethernet, etc.)
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst

    # ----------------------------------------------------------
    # Phase 6: Measure the packet's size BEFORE acquiring the lock.
    #
    # len(packet) returns the full byte length of the captured
    # frame, including ALL headers and payload:
    #   - Ethernet header  : 14 bytes
    #   - IP header        : 20 bytes (minimum)
    #   - TCP/UDP header   : variable
    #   - Application data : variable
    #
    # Example: a small HTTPS response might be ~100 bytes total.
    # A large file-transfer packet might be ~1500 bytes (one MTU).
    #
    # Measuring OUTSIDE the lock avoids holding it while Python
    # inspects the packet object — a tiny performance improvement.
    # ----------------------------------------------------------
    packet_size = len(packet)

    # Acquire the lock before touching any shared data
    with lock:

        # ======================================================
        # PHASE 3 — PROTOCOL COUNTERS
        # ======================================================
        counters["total"] += 1

        if packet.haslayer(TCP):
            counters["tcp"] += 1
        elif packet.haslayer(UDP):
            counters["udp"] += 1
        elif packet.haslayer(ICMP):
            counters["icmp"] += 1
        else:
            counters["other"] += 1

        # ======================================================
        # PHASE 4 — TOP IP TRACKER
        # ======================================================
        ip_tracker[src_ip] += 1
        ip_tracker[dst_ip] += 1

        # ======================================================
        # PHASE 5 — PORT ANALYSIS
        # ======================================================
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            port_tracker[tcp_layer.sport] += 1
            port_tracker[tcp_layer.dport] += 1
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            port_tracker[udp_layer.sport] += 1
            port_tracker[udp_layer.dport] += 1

        # ======================================================
        # PHASE 6 — BANDWIDTH TRACKING (NEW)
        # ======================================================
        #
        # total_bytes    — running total across ALL windows.
        #                  Tells us how much data we've seen overall.
        #
        # window_bytes   — only this window's bytes.
        #                  print_stats() divides this by elapsed
        #                  seconds to get the "current speed."
        #
        # window_packets — only this window's packet count.
        #                  Used for the packets/sec display.
        #
        # ======================================================
        bandwidth["total_bytes"]    += packet_size
        bandwidth["window_bytes"]   += packet_size
        bandwidth["window_packets"] += 1


# =============================================================
#   HELPER: format_bytes(num_bytes)
# =============================================================
#   Converts a raw byte count into the most readable unit.
#
#   Uses binary (base-1024) units — the standard for network
#   and system monitoring tools:
#     1 KB = 1,024 bytes
#     1 MB = 1,024 KB  = 1,048,576 bytes
#     1 GB = 1,024 MB  = 1,073,741,824 bytes
#
#   Examples:
#     format_bytes(512)           → "512 B"
#     format_bytes(2048)          → "2.00 KB"
#     format_bytes(5_242_880)     → "5.00 MB"
#     format_bytes(2_147_483_648) → "2.00 GB"
#
#   This function is called for BOTH speed (bytes/sec)
#   and cumulative total (total_bytes). The caller appends
#   "/s" to the result when displaying speed.
# =============================================================
def format_bytes(num_bytes):

    GB = 1024 ** 3    # 1,073,741,824 — one gibibyte
    MB = 1024 ** 2    # 1,048,576     — one mebibyte
    KB = 1024         # 1,024         — one kibibyte

    if num_bytes >= GB:
        return f"{num_bytes / GB:.2f} GB"
    elif num_bytes >= MB:
        return f"{num_bytes / MB:.2f} MB"
    elif num_bytes >= KB:
        return f"{num_bytes / KB:.2f} KB"
    else:
        # num_bytes is an integer, so no decimal needed here
        return f"{int(num_bytes)} B"


# =============================================================
#   HELPER: make_bar(count, max_count, bar_width=20)
# =============================================================
#   Turns a number into a proportional visual bar.
#   The #1 entry always gets a full bar; all others scale down.
#
#   Example: count=75, max_count=100 → "███████████████░░░░░"
# =============================================================
def make_bar(count, max_count, bar_width=20):
    if max_count == 0:
        return " " * bar_width
    filled = int((count / max_count) * bar_width)
    empty  = bar_width - filled
    return "█" * filled + "░" * empty


# =============================================================
#   FUNCTION: print_stats()
# =============================================================
#   Safely reads all shared data, calculates bandwidth rates,
#   resets the measurement window, then prints four blocks:
#
#     Block 1 — Protocol Statistics      (Phase 3)
#     Block 2 — Top 10 Active IPs        (Phase 4)
#     Block 3 — Top 10 Active Ports      (Phase 5)
#     Block 4 — Bandwidth Monitor        (Phase 6 — NEW)
# =============================================================
def print_stats():

    # ----------------------------------------------------------
    # Snapshot — collect everything under the lock.
    #
    # We also RESET the window counters inside the lock so that
    # no packets can slip into the old window after we've read it.
    #
    # Strategy: read → reset → release. Fast and safe.
    # ----------------------------------------------------------
    with lock:
        total = counters["total"]
        tcp   = counters["tcp"]
        udp   = counters["udp"]
        icmp  = counters["icmp"]
        other = counters["other"]

        top_ips   = ip_tracker.most_common(10)
        top_ports = port_tracker.most_common(10)

        # --- Bandwidth snapshot ---
        total_bytes    = bandwidth["total_bytes"]
        window_bytes   = bandwidth["window_bytes"]
        window_packets = bandwidth["window_packets"]
        window_start   = bandwidth["window_start"]

        # Reset the measurement window for the next 5-second interval.
        # window_start is set to right now so the next elapsed
        # calculation begins from this exact moment.
        bandwidth["window_bytes"]   = 0
        bandwidth["window_packets"] = 0
        bandwidth["window_start"]   = time.time()

    # ----------------------------------------------------------
    # Throughput Calculations (done OUTSIDE the lock — no risk)
    #
    # elapsed = actual seconds this window lasted.
    #           Measured precisely to avoid cumulative drift.
    #
    # bytes_per_sec   = bytes   seen this window / elapsed seconds
    # packets_per_sec = packets seen this window / elapsed seconds
    # ----------------------------------------------------------
    now     = time.time()
    elapsed = now - window_start

    if elapsed > 0:
        bytes_per_sec   = window_bytes   / elapsed
        packets_per_sec = window_packets / elapsed
    else:
        # Extremely unlikely, but guard against division-by-zero
        bytes_per_sec   = 0.0
        packets_per_sec = 0.0

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Percentage helper — safe when total is 0
    def pct(value):
        return (value / total * 100) if total > 0 else 0.0

    # ==========================================================
    # BLOCK 1 — PROTOCOL STATISTICS (Phase 3)
    # ==========================================================
    print("\n" + "═" * 44)
    print("   📊  NETSCOPE AI — LIVE STATISTICS")
    print(f"   🕐  Snapshot at : {timestamp}")
    print("═" * 44)
    print(f"   Total Packets  : {total}")
    print(f"   TCP  Packets   : {tcp:<6}  ({pct(tcp):.1f}%)")
    print(f"   UDP  Packets   : {udp:<6}  ({pct(udp):.1f}%)")
    print(f"   ICMP Packets   : {icmp:<6}  ({pct(icmp):.1f}%)")
    print(f"   Other Packets  : {other:<6}  ({pct(other):.1f}%)")

    # ==========================================================
    # BLOCK 2 — TOP 10 ACTIVE IP ADDRESSES (Phase 4)
    # ==========================================================
    print("═" * 44)
    print("   🏆  TOP 10 ACTIVE IP ADDRESSES")
    print("═" * 44)

    if not top_ips:
        print("   ⏳  Waiting for IP traffic...")
    else:
        max_ip_count = top_ips[0][1]
        for rank, (ip, count) in enumerate(top_ips, start=1):
            bar = make_bar(count, max_ip_count)
            print(f"   {rank:<3} {ip:<18} {bar}  {count}")

    # ==========================================================
    # BLOCK 3 — TOP 10 PORTS (Phase 5)
    # ==========================================================
    print("═" * 44)
    print("   🚪  TOP 10 PORTS")
    print("═" * 44)

    if not top_ports:
        print("   ⏳  Waiting for TCP/UDP traffic...")
    else:
        max_port_count = top_ports[0][1]
        for rank, (port, count) in enumerate(top_ports, start=1):
            service = COMMON_PORTS.get(port, "UNKNOWN")
            bar     = make_bar(count, max_port_count)
            print(
                f"   {rank:<3} "
                f"{port:<6} "
                f"{service:<12} "
                f"{bar} "
                f"{count}"
            )

    # ==========================================================
    # BLOCK 4 — BANDWIDTH MONITOR (NEW IN PHASE 6)
    # ==========================================================
    #
    # Current Speed  → bytes_per_sec expressed in the best unit
    #                  (e.g. "4.77 MB/s", "512 B/s")
    #
    # Bytes/sec      → raw integer — useful for logging / scripts
    #
    # Packets/sec    → floating-point packet rate this window
    #
    # Total Data     → all bytes seen since program started,
    #                  in the best readable unit
    #
    # ==========================================================
    print("═" * 44)
    print("   📡  BANDWIDTH MONITOR")
    print("═" * 44)
    print(f"   Current Speed  : {format_bytes(bytes_per_sec)}/s")
    print(f"   Bytes/sec      : {bytes_per_sec:,.0f}")
    print(f"   Packets/sec    : {packets_per_sec:.1f}")
    print(f"   Total Data     : {format_bytes(total_bytes)}")
    print("═" * 44)

    if total == 0:
        print("   ⏳  No IP packets captured yet — stay tuned!")
        print("═" * 44)


# =============================================================
#   FUNCTION: start_sniffing()
# =============================================================
#   Wrapper for Scapy's sniff(). Runs in a background thread.
#   prn   → callback: analyze_packet is called per packet
#   store → False: don't accumulate packets in RAM
#   count → 0: run forever until the program exits
# =============================================================
def start_sniffing():
    sniff(
        prn=analyze_packet,
        store=False,
        count=0
    )


# =============================================================
#   MAIN — Entry Point
# =============================================================
#   Design:
#     Thread 1 (daemon) → sniff() runs non-stop in background
#     Thread 2 (main)   → sleeps 5 sec, prints stats, repeat
#
#   daemon=True ensures the sniffer thread dies automatically
#   when the main thread exits — no zombie processes.
# =============================================================

# Create and start the background sniffer thread
sniffer_thread = threading.Thread(
    target=start_sniffing,
    daemon=True,
    name="PacketSniffer"
)
sniffer_thread.start()

# Startup banner
print("\n" + "═" * 44)
print("   🚀  NetScope AI — Phase 6 Active")
print("   📡  Packet sniffer running in background")
print("   🏆  Top Talkers enabled")
print("   🚪  Port Analysis enabled")
print("   📊  Bandwidth Monitor enabled")
print("   🔄  Stats refresh every 5 seconds")
print("   ⏹   Press Ctrl+C to stop")
print("═" * 44)

# Main loop: sleep 5 seconds, print stats, repeat
try:
    while True:
        time.sleep(5)
        print_stats()

except KeyboardInterrupt:
    # Ctrl+C: print one final snapshot before quitting
    print("\n")
    print("   🛑  Ctrl+C detected")
    print("   📊  Printing final snapshot...\n")
    print_stats()
    print("\n")
    print("   ✅  NetScope AI Phase 6 complete")
    print("   🎯  Ready for Phase 7!")
    print("\n")
