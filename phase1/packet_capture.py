from scapy.all import sniff

def packet_detected(packet):
    print("Packet detected!")

sniff(prn=packet_detected, store=False)