# CodeAlpha Cybersecurity Internship Project
# Enhanced Network Packet Sniffer using scapy
from scapy.all import sniff, TCP, UDP, IP, ICMP
from scapy.utils import wrpcap
from colorama import init, Fore, Style
import time
import csv
import os

init(autoreset=True)

packets_list = []

common_ports = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP-SERVER',
    68: 'DHCP-CLIENT',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    123: 'NTP',
    135: 'MS RPC',
    137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP-TRAP',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    587: 'SMTP (MS)',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    1723: 'PPTP',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-ALT',
    27017: 'MongoDB',
    5000: 'Flask',
    8000: 'HTTP-ALT2',
    8443: 'HTTPS-ALT'
}
# create directories for storing session and capture files
script_dir = os.path.dirname(os.path.abspath(__file__))
sessions_dir = os.path.join(script_dir, "sessions")
os.makedirs(sessions_dir, exist_ok=True)

filename = os.path.join(sessions_dir, f"session_{int(time.time())}.csv")

with open(filename, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Payload'])

# create directories for storing Wireshark format captures
script_dir = os.path.dirname(os.path.abspath(__file__))
captures_dir = os.path.join(script_dir, "Wireshark_format_captures")
os.makedirs(captures_dir, exist_ok=True)

pcap_filename = os.path.join(captures_dir, f"full_capture_{int(time.time())}.pcap")


def check_port(port):
    return common_ports.get(port, str(port))

def process_packet(packet):
    packets_list.append(packet)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    if not packet.haslayer(IP):
        print(f"{Fore.RED}Non-IP Packet: {packet.summary()}{Style.RESET_ALL}")
        return
    if not packet.haslayer(TCP) and not packet.haslayer(UDP) and not packet.haslayer(ICMP):
        print(f"{Fore.RED}Unsupported Layer: {packet.summary()}{Style.RESET_ALL}")
        return
    
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto

    print(f"\n{Fore.BLUE}IP Packet: FROM:: {src_ip} -> TO:: {dst_ip} | Protocol: {protocol}{Style.RESET_ALL}")
    
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags
        print(f"{Fore.GREEN}TCP Packet: FROM:: {src_port} -> TO:: {dst_port}{Style.RESET_ALL}")
        payload = bytes(tcp.payload)[:50].hex()
        if payload:
            try:
                print(f"{Fore.MAGENTA}Payload: {payload}{Style.RESET_ALL}")
            except:
                print(f"{Fore.MAGENTA}Payload: Non-decodable data{Style.RESET_ALL}")


    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        print(f"{Fore.YELLOW}UDP Packet: FROM:: {src_port} -> TO:: {dst_port}{Style.RESET_ALL}")
        payload = bytes(udp.payload)[:50].hex()
        if payload:
            try:
                print(f"{Fore.MAGENTA}Payload: {payload}{Style.RESET_ALL}")
            except:
                print(f"{Fore.MAGENTA}Payload: Non-decodable data{Style.RESET_ALL}")
    

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"{Fore.CYAN}ICMP Packet: FROM:: {icmp.type}, code {icmp.code}{Style.RESET_ALL}")
        payload = bytes(icmp.payload)[:50].hex()
        if payload:
            print(f"{Fore.MAGENTA}Payload: {payload}{Style.RESET_ALL}")
    
    else:
        print(f"Other IP Packet: {packet.summary()}")

    with open(filename, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, protocol, src_ip, src_port, dst_ip, dst_port, payload])

def main():
    print("📡 CodeAlpha Cybersecurity Internship Project")
    print("🚀 Enhanced Network Packet Sniffer")
    print("🚀 Sniffer started... Press Ctrl+C to stop.")

    try: 
        while True:
            # Capture 10 packets every 5 seconds
            sniff(count=10, prn=process_packet, filter="ip", store=False)
            print("\n⏸ Waiting 5 seconds before next batch...\n")
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n🛑 Sniffer stopped!.")
        wrpcap(pcap_filename, packets_list)
        print(f"Full packet capture saved to: {pcap_filename}")
        print(f"Session data saved to: {filename}")
if __name__ == "__main__":
    main()

