from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        time = datetime.now().strftime("%H:%M:%S")

        print(f"[{time}] {src} -> {dst} | Protocol: {proto}")

        if TCP in packet:
            print(f"  TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"  UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}")

        print("-" * 60)

print("🟢 Sniffing started... Press Ctrl+C to stop.")
sniff(prn=process_packet, store=0)
