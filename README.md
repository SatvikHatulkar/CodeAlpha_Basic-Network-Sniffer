# Network Packet Sniffer — CodeAlpha Task

This project is a Python **Network Packet Sniffer** developed as part of a CodeAlpha internship task

It captures live network packets on your machine, shows important details like protocol, source/destination IPs and ports, and saves all raw packets into a `.pcap` file you can open in **Wireshark**.

---

## Features

- **Capture live network traffic**
- **Filter by protocol** (TCP, UDP, ICMP, IP)
- **Filter by port number**
- **Save captured packets** to a `.pcap` file (compatible with Wireshark)
- **Optional payload display** (show raw payloads in the terminal)
- **Clean, simple command-line interface**

---

## Installation
```bash
git clone https://github.com/SatvikHatulkar/CodeAlpha_Basic-Network-Sniffer.git
cd CodeAlpha_Basic-Network-Sniffer
pip install -r requirements.txt
python3 main.py --help
```