# =============================================================
#   NetScope AI — Phase 4: Top IP Tracker (Top Talkers)
#   Project: Real-Time Network Traffic Analyzer
# =============================================================
#   What's new in Phase 4 (builds on Phase 3):
#   - Tracks how many times every IP address appears
#   - Counts both Source IPs and Destination IPs
#   - Every 5 seconds shows a ranked Top 10 IP leaderboard
#   - Adds a visual traffic bar so you can spot heavy hitters fast
#   - All Phase 3 counters (Total, TCP, UDP, ICMP) still work
# =============================================================

# scapy.all   → Packet capture and protocol layer detection
# threading   → Run sniffer and reporter simultaneously
# time        → 5-second sleep interval between reports
# datetime    → Timestamp each statistics snapshot
# collections → Counter: a dictionary built for counting things
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from datetime import datetime
from collections import Counter


# =============================================================
#   SECTION 1 — PROTOCOL COUNTERS (Carried over from Phase 3)
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
#   SECTION 2 — IP ADDRESS TRACKER (New in Phase 4)
# =============================================================
#   collections.Counter is a special dictionary where:
#     - Keys   → IP addresses  (e.g. "192.168.1.5")
#     - Values → packet counts (e.g. 143)
#
#   It behaves exactly like a regular dict but adds:
#     ip_tracker["192.168.1.5"] += 1  → works even if key is new
#     ip_tracker.most_common(10)      → returns top 10 instantly
#
#   We track BOTH source and destination IPs in the same Counter.
#   Why? Because a busy IP appears as both sender and receiver,
#   and combining them gives the truest picture of total activity.
# =============================================================
ip_tracker = Counter()


# =============================================================
#   SECTION 3 — THREAD LOCK (Same role as Phase 3)
# =============================================================
#   One lock protects ALL shared data: counters + ip_tracker.
#   Only one thread may read or write at a time.
# =============================================================
lock = threading.Lock()


# =============================================================
#   FUNCTION: analyze_packet(packet)
# =============================================================
#   Called by Scapy for every captured packet.
#   Jobs:
#     1. Skip non-IP packets
#     2. Update protocol counters  (Phase 3)
#     3. Update IP tracker         (Phase 4 — NEW)
# =============================================================
def analyze_packet(packet):

    # Skip anything without an IP layer (ARP, raw Ethernet, etc.)
    if not packet.haslayer(IP):
        return

    # Pull out the IP layer so we can read its fields
    ip_layer = packet[IP]

    # Read Source IP and Destination IP from the IP header
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Acquire the lock before touching any shared data
    with lock:

        # --- Phase 3: Protocol counters ---
        counters["total"] += 1

        if packet.haslayer(TCP):
            counters["tcp"] += 1
        elif packet.haslayer(UDP):
            counters["udp"] += 1
        elif packet.haslayer(ICMP):
            counters["icmp"] += 1
        else:
            counters["other"] += 1

        # --- Phase 4: IP address tracking (NEW) ---
        # Increment the count for the source IP.
        # Counter handles brand-new keys automatically (starts at 0).
        ip_tracker[src_ip] += 1

        # Increment the count for the destination IP.
        # Same IP can appear as both src and dst — that's intentional.
        # A server that sends and receives a lot is genuinely very active.
        ip_tracker[dst_ip] += 1


# =============================================================
#   HELPER: make_bar(count, max_count, bar_width=20)
# =============================================================
#   Turns a number into a visual bar made of block characters.
#   Example: count=75, max_count=100 → "███████████████     "
#
#   This is called a "proportional bar chart."
#   The longest bar always belongs to rank #1 (the max).
#   All other bars are drawn relative to it.
# =============================================================
def make_bar(count, max_count, bar_width=20):
    if max_count == 0:
        return " " * bar_width
    # How many filled blocks? Proportional to count / max_count
    filled = int((count / max_count) * bar_width)
    empty  = bar_width - filled
    return "█" * filled + "░" * empty


# =============================================================
#   FUNCTION: print_stats()
# =============================================================
#   Reads all shared data safely, then prints:
#     - Protocol counters summary  (Phase 3)
#     - Top 10 IP leaderboard      (Phase 4)
# =============================================================
def print_stats():

    # Take a consistent snapshot of all shared data under the lock.
    # We copy the values out so the lock is held as briefly as possible.
    with lock:
        total = counters["total"]
        tcp   = counters["tcp"]
        udp   = counters["udp"]
        icmp  = counters["icmp"]
        other = counters["other"]

        # most_common(10) returns a list of (ip, count) tuples,
        # sorted from highest count to lowest. Example:
        # [("8.8.8.8", 240), ("192.168.1.1", 180), ...]
        top_ips = ip_tracker.most_common(10)

    # Current time for the snapshot label
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Percentage helper — avoids ZeroDivisionError when total is 0
    def pct(n):
        return (n / total * 100) if total > 0 else 0.0

    # ── Phase 3 block: Protocol Summary ──────────────────────────
    print("\n" + "═" * 44)
    print(f"   📊  NETSCOPE AI — LIVE STATISTICS")
    print(f"   🕐  Snapshot at : {timestamp}")
    print("═" * 44)
    print(f"   Total Packets  : {total}")
    print(f"   TCP  Packets   : {tcp:<6}  ({pct(tcp):.1f}%)")
    print(f"   UDP  Packets   : {udp:<6}  ({pct(udp):.1f}%)")
    print(f"   ICMP Packets   : {icmp:<6}  ({pct(icmp):.1f}%)")
    print(f"   Other Packets  : {other:<6}  ({pct(other):.1f}%)")

    # ── Phase 4 block: Top 10 Active IP Addresses ─────────────────
    print("═" * 44)
    print(f"   🏆  TOP 10 ACTIVE IP ADDRESSES")
    print("═" * 44)

    if not top_ips:
        # No IP packets have been seen yet
        print("   ⏳  Waiting for IP traffic...")
    else:
        # The highest count drives the bar chart scale
        max_count = top_ips[0][1]

        # Print each IP with its rank, bar, and count
        for rank, (ip, count) in enumerate(top_ips, start=1):
            bar  = make_bar(count, max_count)
            # :<3  → left-align rank in 3 chars (handles 1–10 neatly)
            # :<18 → left-align IP address in 18 chars (fits IPv4 + padding)
            print(f"   {rank:<3} {ip:<18} {bar}  {count}")

    print("═" * 44)

    if total == 0:
        print("   ⏳  No IP packets captured yet — stay tuned!")
        print("═" * 44)


# =============================================================
#   FUNCTION: start_sniffing()
# =============================================================
#   Wrapper for Scapy's sniff(). Runs in a background thread.
#   prn      → callback: analyze_packet is called per packet
#   store    → False: don't accumulate packets in RAM
#   count    → 0: run forever until the program exits
# =============================================================
def start_sniffing():
    sniff(prn=analyze_packet, store=False, count=0)


# =============================================================
#   MAIN — Entry Point
# =============================================================
#   Design:
#     Thread 1 (daemon) → sniff() runs non-stop in background
#     Thread 2 (main)   → sleeps 5 sec, prints stats, repeat
#
#   daemon=True: background thread dies automatically when
#   the main thread exits (no zombie processes).
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
print("   🚀  NetScope AI — Phase 4 Active")
print("   📡  Packet sniffer running in background")
print("   🏆  Top IP tracker is live")
print("   📊  Stats refresh every 5 seconds")
print("   ⏹   Press Ctrl+C to stop")
print("═" * 44)

# Main loop: sleep 5 seconds, print stats, repeat
try:
    while True:
        time.sleep(5)
        print_stats()

except KeyboardInterrupt:
    # Ctrl+C: print one final snapshot before quitting
    print("\n\n   🛑  Stopping — printing final snapshot...\n")
    print_stats()
    print("\n   ✅  NetScope AI Phase 4 complete. See you in Phase 5!\n")