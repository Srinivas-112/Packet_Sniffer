# Packet Sniffer in Python

This is a simple **Packet Sniffer** built using Python and `scapy` that captures network packets and displays key details such as MAC addresses, IP addresses, and protocols (TCP, UDP, ICMP).  

## Features
- Captures **Ethernet frames** (MAC addresses).
- Supports **IPv4 packets**.
- Detects **TCP, UDP, and ICMP protocols**.
- Displays **source and destination IPs & ports**.

## Prerequisites
- **Python 3.6+** installed  
- **Scapy library** installed  
- **Npcap** or **WinPcap** installed (required for Windows)

## Installation

### 1. Install Python Packages  
```bash
pip install scapy
