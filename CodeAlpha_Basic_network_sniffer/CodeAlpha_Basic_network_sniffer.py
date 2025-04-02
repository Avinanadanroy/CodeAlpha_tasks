from scapy.all import *

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto  # Protocol number
        print(f"IP Packet: Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}")

        # Further analyze TCP packets
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: Source Port: {tcp_sport}, Destination Port: {tcp_dport}")

        # Further analyze UDP packets
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Packet: Source Port: {udp_sport}, Destination Port: {udp_dport}")

        # Further analyze ICMP packets
        elif ICMP in packet:
            print("ICMP Packet detected")

        # Print a summary of the packet
        print(packet.summary())

def start_sniffer(interface=None, packet_count=10):
    print(f"Starting the sniffer to capture {packet_count} packets...")
    sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (or press Enter for default): ")
    start_sniffer(interface if interface else None)