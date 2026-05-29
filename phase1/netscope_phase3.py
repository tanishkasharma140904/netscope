# =============================================================
#   NetScope AI — Phase 3: Live Traffic Statistics
#   Project: Real-Time Network Traffic Analyzer
# =============================================================
#   What this phase adds:
#   - Counts every IP packet that arrives (Total, TCP, UDP, ICMP)
#   - Does NOT print individual packets anymore
#   - Every 5 seconds, prints a clean statistics summary
#   - Uses threading so sniffing and reporting run simultaneously
# =============================================================

# scapy.all  → Packet capture and layer detection
# threading  → Run the sniffer and the stats printer at the same time
# time       → Used for the 5-second sleep interval
# datetime   → Adds a timestamp to each statistics report
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from datetime import datetime


# =============================================================
#   COUNTERS — The Core Data of Phase 3
# =============================================================
#   We use a dictionary to store all our packet counts in one
#   place. A dictionary is like a labelled box — each label
#   (key) holds a number (value) that we update over time.
#
#   Why a dictionary instead of separate variables?
#   → Cleaner to pass around, easier to expand later (Phase 4+).
# =============================================================
counters = {
    "total" : 0,   # Every IP packet seen
    "tcp"   : 0,   # TCP packets only
    "udp"   : 0,   # UDP packets only
    "icmp"  : 0,   # ICMP packets only
    "other" : 0,   # IP packets with a protocol we don't name above
}


# =============================================================
#   THREAD LOCK — Preventing a Silent Bug Called a Race Condition
# =============================================================
#   Our program has TWO threads running at the same time:
#     Thread 1 (Sniffer)  → updates the counters constantly
#     Thread 2 (Reporter) → reads the counters every 5 seconds
#
#   Without a lock, both threads could touch the same counter
#   at the exact same millisecond, causing corrupted numbers.
#   A Lock is like a "do not disturb" sign — only one thread
#   can hold it at a time. The other waits its turn.
# =============================================================
lock = threading.Lock()


# =============================================================
#   FUNCTION: analyze_packet(packet)
# =============================================================
#   Called automatically by Scapy for every captured packet.
#   Its only job: increment the right counters.
#   It no longer prints anything — stats are handled separately.
# =============================================================
def analyze_packet(packet):

    # Ignore packets without an IP layer (e.g. ARP, raw Ethernet)
    if not packet.haslayer(IP):
        return

    # Acquire the lock before touching shared counter data.
    # "with lock:" means: grab the lock, do the work, release it.
    # This keeps our counter numbers accurate and safe.
    with lock:

        # Every IP packet increments the total counter
        counters["total"] += 1

        # Check which transport protocol this packet uses
        # and increment only that counter.
        # We use elif (not separate ifs) because a packet can
        # only have one primary transport layer at a time.
        if packet.haslayer(TCP):
            counters["tcp"] += 1
        elif packet.haslayer(UDP):
            counters["udp"] += 1
        elif packet.haslayer(ICMP):
            counters["icmp"] += 1
        else:
            # Catches valid IP packets with unusual protocols
            # (e.g. GRE tunnelling, OSPF routing protocol, etc.)
            counters["other"] += 1


# =============================================================
#   FUNCTION: print_stats()
# =============================================================
#   Reads the current counter values and prints a formatted
#   summary report. Called by the main thread every 5 seconds.
# =============================================================
def print_stats():

    # Read the counters inside a lock to get a consistent
    # snapshot. Without this, counters could change mid-read.
    with lock:
        total = counters["total"]
        tcp   = counters["tcp"]
        udp   = counters["udp"]
        icmp  = counters["icmp"]
        other = counters["other"]

    # Timestamp so each report shows exactly when it was taken
    timestamp = datetime.now().strftime("%H:%M:%S")

    # --- Compute percentage breakdowns (guard against /0) ---
    # If total is 0 (no packets yet), percentages stay at 0.0
    # Otherwise, divide each count by total and multiply by 100.
    def pct(count):
        return (count / total * 100) if total > 0 else 0.0

    # --- Print the formatted statistics block ---
    print("\n" + "=" * 40)
    print(f"   📊  NETSCOPE AI — LIVE STATISTICS")
    print(f"   🕐  Snapshot at : {timestamp}")
    print("=" * 40)
    print(f"   Total Packets  : {total}")
    print(f"   TCP  Packets   : {tcp:<6}  ({pct(tcp):.1f}%)")
    print(f"   UDP  Packets   : {udp:<6}  ({pct(udp):.1f}%)")
    print(f"   ICMP Packets   : {icmp:<6}  ({pct(icmp):.1f}%)")
    print(f"   Other Packets  : {other:<6}  ({pct(other):.1f}%)")
    print("=" * 40)

    # Friendly note if no IP packets have arrived yet
    if total == 0:
        print("   ⏳  No IP packets captured yet. Stay tuned...")
        print("=" * 40)


# =============================================================
#   FUNCTION: start_sniffing()
# =============================================================
#   A tiny wrapper around Scapy's sniff() function.
#   We wrap it so it can be handed to a Thread object cleanly.
# =============================================================
def start_sniffing():
    # sniff() blocks forever (count=0), calling analyze_packet
    # for every captured packet. store=False keeps RAM usage low.
    sniff(prn=analyze_packet, store=False, count=0)


# =============================================================
#   MAIN — Program Entry Point
# =============================================================
#   Strategy:
#     1. Launch the sniffer in a BACKGROUND (daemon) thread.
#        → It runs silently, updating counters non-stop.
#     2. The MAIN thread enters a loop:
#        → Sleep 5 seconds, then call print_stats().
#        → Repeat until the user presses Ctrl+C.
#
#   Why daemon=True on the sniffer thread?
#   → A daemon thread is a "background worker" that automatically
#     shuts down when the main program exits. Without daemon=True,
#     pressing Ctrl+C would stop the main thread but leave the
#     sniffer running invisibly in the background — a ghost process.
# =============================================================

# --- Create the sniffer thread (does NOT start yet) ---
sniffer_thread = threading.Thread(
    target=start_sniffing,
    daemon=True,           # Dies automatically when main thread exits
    name="PacketSniffer"   # A name helps with debugging later
)

# --- Start the sniffer thread (NOW it begins capturing) ---
sniffer_thread.start()

# --- Startup Banner ---
print("\n" + "=" * 40)
print("   🚀  NetScope AI — Phase 3 Active")
print("   📡  Sniffer is running in background...")
print("   📊  Stats will print every 5 seconds.")
print("   ⏹   Press Ctrl+C to stop.")
print("=" * 40)

# --- Main Loop: print stats every 5 seconds ---
try:
    while True:
        # Pause the main thread for 5 seconds.
        # During this sleep, the sniffer thread keeps running
        # and updating counters in the background.
        time.sleep(5)

        # After 5 seconds, print the current statistics
        print_stats()

except KeyboardInterrupt:
    # This runs when the user presses Ctrl+C
    # Print one final stats snapshot before quitting
    print("\n\n   🛑  Ctrl+C detected — printing final stats...\n")
    print_stats()
    print("\n   ✅  NetScope AI Phase 3 stopped. See you in Phase 4!\n")
