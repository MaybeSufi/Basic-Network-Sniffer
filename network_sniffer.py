from scapy.all import Ether, IP, TCP, UDP, sniff

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto


        if proto == 6:
            protocol = "TCP"
            
            if packet.haslayer(TCP):
                payload_len = len(packet[TCP].payload)
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"TCP | {ip_src}: {sport} -> {ip_dst}: {dport} | Length: {payload_len}")

            else:
                print(f"Other IP Protocol {proto}| {ip_src} -> {ip_dst}")

        


print("Starting sniffer...........")
sniff(iface= None, prn=packet_callback, store=0, count=10)