# =============================================================
#   NetScope AI — Phase 2: IP Traffic Analyzer
#   Project: Real-Time Network Traffic Analyzer
# =============================================================
#   What this script does:
#   - Captures live network packets using Scapy
#   - Ignores any packet that does NOT have an IP layer
#   - For every IP packet, displays:
#       * Source IP Address
#       * Destination IP Address
#       * Protocol Type (TCP, UDP, ICMP, or Other)
# =============================================================

# Import Scapy's core tools:
# - sniff : the function that captures live packets
# - IP    : represents the IP layer inside a packet
# - TCP   : represents the TCP layer
# - UDP   : represents the UDP layer
# - ICMP  : represents the ICMP layer
from scapy.all import sniff, IP, TCP, UDP, ICMP


# ---------------------------------------------------------------
#  FUNCTION: analyze_packet(packet)
# ---------------------------------------------------------------
#  Scapy calls this function automatically every time a new
#  packet is captured from the network interface.
#  Think of it as: "For every packet that arrives, do THIS."
# ---------------------------------------------------------------
def analyze_packet(packet):

    # --- STEP 1: Filter out non-IP packets ---
    # Not every packet on the network has an IP layer.
    # Example: ARP packets (used for MAC address lookup) don't.
    # packet.haslayer(IP) returns True only if the packet
    # contains an IP header. If it doesn't, we skip it.
    if not packet.haslayer(IP):
        return  # Ignore this packet and wait for the next one

    # --- STEP 2: Extract the IP layer ---
    # packet[IP] gives us access to everything inside the
    # IP header — like source address, destination address, etc.
    ip_layer = packet[IP]

    # --- STEP 3: Get the Source IP Address ---
    # ip_layer.src is the IP address of the machine/device
    # that SENT this packet (the origin).
    src_ip = ip_layer.src

    # --- STEP 4: Get the Destination IP Address ---
    # ip_layer.dst is the IP address of the machine/device
    # that should RECEIVE this packet (the target).
    dst_ip = ip_layer.dst

    # --- STEP 5: Determine the Protocol ---
    # After the IP layer, packets carry a transport-layer protocol.
    # We check which protocol is present by looking for layers:
    #   TCP  (Transmission Control Protocol) — reliable, ordered
    #   UDP  (User Datagram Protocol)        — fast, no guarantee
    #   ICMP (Internet Control Message)      — used by ping/traceroute
    #   Other — any protocol we haven't named above
    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        # Could be protocols like GRE, OSPF, SCTP, etc.
        protocol = "Other"

    # --- STEP 6: Display the results neatly ---
    # We use an f-string to embed variable values inside the text.
    # The dashes create a visual separator between packets.
    print("─" * 52)
    print(f"  📦  New Packet Captured!")
    print(f"  🔵  Source IP       : {src_ip}")
    print(f"  🟢  Destination IP  : {dst_ip}")
    print(f"  🔷  Protocol        : {protocol}")
    print("─" * 52)


# ---------------------------------------------------------------
#  MAIN ENTRY POINT: Start the Sniffer
# ---------------------------------------------------------------
#  Everything below this line runs when you execute the script.
# ---------------------------------------------------------------

# Print a startup banner so the user knows the sniffer is active
print("=" * 52)
print("  🚀  NetScope AI — Phase 2 Active")
print("  📡  Listening for IP packets on all interfaces...")
print("  ⏹   Press Ctrl+C to stop.")
print("=" * 52)

# sniff() is the heart of Scapy's packet capture.
#
# Parameters used here:
#   prn=analyze_packet
#       → Every captured packet is passed to our function.
#         "prn" stands for "print function" — a callback.
#
#   store=False
#       → Tells Scapy NOT to keep packets in memory.
#         Without this, RAM usage grows forever. Always use this
#         when capturing for a long time.
#
#   count=0
#       → 0 means "capture indefinitely" until Ctrl+C is pressed.
#         Change to e.g. count=10 to capture exactly 10 packets.
#
# We wrap sniff() in a try/except so that pressing Ctrl+C
# exits cleanly instead of showing a messy error traceback.
try:
    sniff(prn=analyze_packet, store=False, count=0)
except KeyboardInterrupt:
    # This block runs when the user presses Ctrl+C
    print("\n\n  ✅  Sniffer stopped. NetScope AI Phase 2 complete!")
    print("  See you in Phase 3!\n")
