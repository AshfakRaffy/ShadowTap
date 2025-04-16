from scapy.all import DNS, DNSQR, IP

def parse_dns(packet):
    # Check if packet has DNS layer and is a query
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        ip_layer = packet.getlayer(IP)
        dns_layer = packet.getlayer(DNS)
        query = dns_layer.qd

        return {
            'source_ip': ip_layer.src,
            'domain': query.qname.decode().rstrip('.')
        }

    return None

def log_activity(info):
    with open("logs/dns_log.txt", "a") as log_file:
        log_file.write(f"{info['source_ip']} visited {info['domain']}\n")
