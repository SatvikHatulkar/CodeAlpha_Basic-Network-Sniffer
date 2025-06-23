import argparse
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import binascii
from prettytable import PrettyTable
import atexit

# Storage for packets and args
captured_packets = []
args = None  # Holding CLI args globally

def packet_callback(packet, show_payload):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        protocol_name = ""
        details = ""

        if protocol == 1 and ICMP in packet:
            protocol_name = "ICMP"
            icmp_layer = packet[ICMP]
            details = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
        elif protocol == 6 and TCP in packet:
            protocol_name = "TCP"
            tcp_layer = packet[TCP]
            details = f"Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}"
        elif protocol == 17 and UDP in packet:
            protocol_name = "UDP"
            udp_layer = packet[UDP]
            details = f"Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}"
        else:
            protocol_name = "Other"

        payload = bytes(packet[IP].payload.payload)
        if payload:
            payload_hex = binascii.hexlify(payload).decode()
            payload_text = payload.decode('utf-8', errors='replace')
        else:
            payload_hex = "No Payload"
            payload_text = "No Payload"

        table = PrettyTable()
        table.field_names = ["Field", "Value"]
        table.add_row(["Protocol", protocol_name])
        table.add_row(["Source IP", src_ip])
        table.add_row(["Destination IP", dst_ip])
        if details:
            table.add_row(["Details", details])
        if show_payload:
            table.add_row(["Payload (hex)", payload_hex])
            table.add_row(["Payload (text)", payload_text])

        print(table)

        captured_packets.append(packet)

def save_pcap():
    if captured_packets:
        wrpcap(args.output, captured_packets)
        print(f"\n[*] Saved {len(captured_packets)} packets to {args.output}")
    else:
        print("\n[*] No packets captured — nothing saved.")

def main():
    global args

    parser = argparse.ArgumentParser(
        description="Python Packet Sniffer with Filters, Safe Saving, and Optional Payload Display"
    )
    parser.add_argument("--protocol", choices=["tcp", "udp", "icmp", "ip"], default="ip",
                        help="Protocol to filter (default: ip)")
    parser.add_argument("--port", type=int, help="Port number to filter (optional)")
    parser.add_argument("--output", default="capture.pcap",
                        help="Output .pcap file (default: capture.pcap)")
    parser.add_argument("--show-payload", action="store_true",
                        help="Show payload on screen (may clutter)")

    args = parser.parse_args()

    atexit.register(save_pcap)

    if args.show_payload:
        print("WARNING: Showing payload may clutter your terminal!")

    filter_str = args.protocol
    if args.port:
        filter_str += f" port {args.port}"

    print("[*] Starting Packet Sniffer...")
    print(f"[*] Filter: {filter_str}")
    print(f"[*] Output file: {args.output}")
    print(f"[*] Payload display: {'ENABLED' if args.show_payload else 'DISABLED'}")
    print("[*] Press Ctrl+C to stop.\n")

    sniff(prn=lambda pkt: packet_callback(pkt, args.show_payload),
          filter=filter_str,
          store=0)

if __name__ == "__main__":
    main()