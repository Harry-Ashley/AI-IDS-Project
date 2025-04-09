import pickle
import scapy.all as scapy
from termcolor import colored

with open('ml_model.pkl', 'rb') as f:
    model = pickle.load(f)

INTERFACE = 'enp0s3'

ip_encoding = {
    '192.168.1.x': 1,  # Host Machine
    '192.168.1.x': 2,  # Web Server
    '192.168.1.x': 3,  # IDS VM
    '192.168.1.x': 4   # Attacker VM
}

def encode_ip(ip):
    return ip_encoding.get(ip, 0)

def encode_protocol(proto):
    if proto == 6:
        return 1  # TCP
    elif proto == 17:
        return 2  # UDP
    elif proto == 1:
        return 3  # ICMP
    else:
        return 0

def encode_flags(flags):
    if flags == 'PA':
        return 1
    elif flags == 'S':
        return 2
    elif flags == 'FA':
        return 3
    elif flags == 'R':
        return 4
    elif flags == 'P':
        return 5
    elif flags == 'F':
        return 6
    elif flags == 'A':
        return 7
    else:
        return 0

def predict_packet(pkt):
    try:
        if scapy.IP in pkt:
            src_ip = pkt[scapy.IP].src
            dst_ip = pkt[scapy.IP].dst
            proto = pkt[scapy.IP].proto
            ttl = pkt[scapy.IP].ttl
            length = len(pkt)

            if scapy.TCP in pkt:
                src_port = pkt[scapy.TCP].sport
                dst_port = pkt[scapy.TCP].dport
                flags = pkt.sprintf('%TCP.flags%')
            elif scapy.UDP in pkt:
                src_port = pkt[scapy.UDP].sport
                dst_port = pkt[scapy.UDP].dport
                flags = None
            elif scapy.ICMP in pkt:
                src_port = 0
                dst_port = 0
                flags = None
            else:
                src_port = 0
                dst_port = 0
                flags = None

            feature_vector = [
                encode_ip(src_ip),
                encode_ip(dst_ip),
                src_port,
                dst_port,
                encode_protocol(proto),
                length,
                encode_flags(flags),
                ttl
            ]

            prediction = model.predict([feature_vector])

            if prediction[0] == 1:
                print(colored(f"[ALERT] Detected Malicious Traffic: {src_ip} -> {dst_ip}", 'red'))
            else:
                print(colored(f"[OK] Normal Traffic: {src_ip} -> {dst_ip}", 'green'))

    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    print(f"[*] Starting Real-Time Packet Sniffing on {INTERFACE}...")
    scapy.sniff(iface=INTERFACE, prn=predict_packet, store=False)

if __name__ == "__main__":
    main()
