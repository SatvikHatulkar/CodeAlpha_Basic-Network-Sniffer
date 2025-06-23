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

## Example Commands

Below are useful examples you can run directly:

```bash
# Show help and options
sudo python3 main.py --help
```
```bash
# Capture all IP packets (default)
sudo python3 main.py
```
```bash
# Capture TCP packets on port 80 (HTTP)
sudo python3 main.py --protocol tcp --port 80
```
```bash
# Capture UDP packets on port 53 (DNS)
sudo python3 main.py --protocol udp --port 53
```
```bash
# Capture ICMP packets (ping)
sudo python3 main.py --protocol icmp
```
```bash
# Save to a custom .pcap file
sudo python3 main.py --output mycapture.pcap
```
```bash
# Show payloads in the terminal (can clutter)
sudo python3 main.py --show-payload
```
```bash
# Combine filters + output file
sudo python3 main.py --protocol tcp --port 8080 --output webtraffic.pcap
```