from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        src_mac = eth_layer.src
        dst_mac = eth_layer.dst
        print(f"\nEthernet Frame: Src MAC: {src_mac}, Dst MAC: {dst_mac}")

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_version = "IPv4"
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        print(f"IP Packet: {ip_version}, Src IP: {src_ip}, Dst IP: {dst_ip}, Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Segment: Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Segment: Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            print("ICMP Packet Detected")

sniff(prn=packet_callback, store=False)
