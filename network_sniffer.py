from scapy.all import sniff, IP, TCP, UDP, ICMP


def show_packet(packet):
    if IP in packet:

        source = packet[IP].src
        destination = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            source_port = "-"
            destination_port = "-"

        else:
            protocol = "Other"
            source_port = "-"
            destination_port = "-"

        print("Source IP:", source)
        print("Destination IP:", destination)
        print("Protocol:", protocol)
        print("Source Port:", source_port)
        print("Destination Port:", destination_port)
        print("-" * 40)


print("Network Sniffer Started...")

sniff(prn=show_packet, count=10)

print("Finished!")