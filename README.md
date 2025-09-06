# CodeAlpha Cybersecurity Internship Project
## Enhanced Network Packet Sniffer

---

## 📌 Project Overview
This project is an **Enhanced Network Packet Sniffer** built with Python and Scapy.  
It captures network traffic in real-time, separates TCP, UDP, and ICMP packets, previews payloads, and logs packet data into per-session CSV files for easy analysis.  
Additionally, full packet captures are saved in **Wireshark-compatible `.pcap` files** for deep inspection.

---
## ⚙ Features
- Capture TCP, UDP, and ICMP packets.
- Preview packet payloads in console (first 50 bytes as hex).
- Save per-session **CSV files** for easy data review.
- Save full packet captures in **Wireshark `.pcap` format**.
- Automatically organizes session data in folders.
- Shows common **service names for ports**.
- Safe **Ctrl+C exit** with automatic pcap saving.

---

## 🗂 Project Structure
```
CodeAlpha-Network-Sniffer/
│
├── Network_sniffer.py
├── sessions/
│ └── .gitkeep
├── Wireshark_format_captures/
│ └── .gitkeep
├── requirements.txt
└── README.md
```

---

## 📝 Requirements

- **Python 3.10+**
- **Scapy** – For packet sniffing
- **Wireshark** - For full network analysis of .pcap files
  ```bash
  pip install scapy
  ```

## 🚀 How to Run
- Clone the repository
  ```
  git clone https://github.com/IrondiUg/Code_Alpha--Network_Sniffer.git
  cd Code_Alpha--Network_Sniffer
  ```
- Install dependencies
    ```
    pip install -r requirements.txt
  ```
- Run the sniffer
    ```
    python Network_sniffer.py
  ```
## 📊 Usage

Open the CSV files for a quick preview of each session.

Open .pcap files in Wireshark for full packet inspection:

Analyze headers, payloads, and protocols.

Follow TCP/UDP streams for complete conversations.

Apply filters like tcp, udp, icmp, or ip.addr==<your_ip>.


## 🎓 Learning Outcomes

<div align="center">


### **Core Concepts Mastered**

</div>

<table>
<tr>
<td width="50%">

#### 🌐 **Network Fundamentals**
- Capturing and analyzing TCP/IP packets
- Network Layer Understanding

#### 🔒 **Security Principles**
- Monitoring real-time network traffic
- Identifying suspicious or malfunctioned packets
- Basic intruision detection techniques
- Ethical traffic analysis and network auditing

</td>
<td width="50%">

#### 💻 **Practical Skills**
- Using Python libraries for packet sniffing (e.g., scapy, socket)
- Filtering and parsing network traffic by protocol
- Logging and analyzing packet data programmatically
- Designing tools for educational or security testing purposes

#### 🔍 **Analysis Capabilities**
- Packet Header Examination
- Protocol Identification
- Payload Content Analysis
- Real-time Data Processing

</td>
</tr>
</table>


