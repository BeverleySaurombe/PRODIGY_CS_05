from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # Check for TCP packets
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"    Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        # Check for UDP packets
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"    Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")

        # Display raw data if available
        if Raw in packet:
            raw_data = packet[Raw].load
            print(f"    Payload: {raw_data}")
    else:
        print("Non-IP packet detected")

def start_sniffer(interface):
    print(f"[*] Starting packet sniffer on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    start_sniffer(interface)

