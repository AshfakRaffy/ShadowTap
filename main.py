from modules.sniffer import start_sniff
from modules.dns_parser import parse_dns, log_activity

def handle_packet(packet):
    info = parse_dns(packet)
    if info:
        print(f"[DNS] {info['source_ip']} visited {info['domain']}")
        log_activity(info)

if __name__ == "__main__":
    interface = input("Enter your network interface (e.g., Wi-Fi, Ethernet): ")
    start_sniff(interface=interface, packet_handler=handle_packet)
