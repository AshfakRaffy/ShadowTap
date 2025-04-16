from scapy.all import sniff

def start_sniff(interface, packet_handler):
    sniff(iface=interface, prn=packet_handler, store=False)
