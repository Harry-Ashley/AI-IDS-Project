import csv
import scapy.all as scapy
from datetime import datetime
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Define the CSV file
csv_file = "captured_packets.csv"

# Define the fields to capture
fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'length', 'flags', 'ttl']

# Create the CSV and write the header
with open(csv_file, mode='w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()


# Packet processing function
def process_packet(packet):
    packet_data = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else 'N/A',
        'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else 'N/A',
        'src_port': packet[scapy.TCP].sport if packet.haslayer(scapy.TCP) else (
            packet[scapy.UDP].sport if packet.haslayer(scapy.UDP) else 'N/A'),
        'dst_port': packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else (
            packet[scapy.UDP].dport if packet.haslayer(scapy.UDP) else 'N/A'),
        'protocol': 'TCP' if packet.haslayer(scapy.TCP) else (
            'UDP' if packet.haslayer(scapy.UDP) else ('ICMP' if packet.haslayer(scapy.ICMP) else 'Other')),
        'length': len(packet),
        'flags': packet[scapy.TCP].flags if packet.haslayer(scapy.TCP) else 'N/A',
        'ttl': packet[scapy.IP].ttl if packet.haslayer(scapy.IP) else 'N/A'
    }

    with open(csv_file, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writerow(packet_data)

    logging.info(f"Packet captured: {packet_data}")


# Start capturing packets
logging.info("Starting packet capture on interface 'enp0s3'. Press Ctrl+C to stop.")
try:
    scapy.sniff(iface="enp0s3", prn=process_packet, store=False)
except KeyboardInterrupt:
    logging.info("Packet capture stopped.")
