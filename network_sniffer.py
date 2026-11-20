#!/usr/bin/env python3
"""
Basic Network Sniffer
---------------------
Captures live network packets using Scapy and displays, for each packet:
timestamp, protocol, source/destination IP and port, packet length,
TCP flags, DNS queries, ARP requests and a readable payload preview.
At the end it prints a capture summary and can save packets to a .pcap file.

Author : Ali Abbas Qazi
Usage  : python network_sniffer.py --list
         python network_sniffer.py -i "Wi-Fi" -c 50
         python network_sniffer.py -f "icmp or udp port 53"
         python network_sniffer.py -c 100 -o capture.pcap
"""

import argparse
import os
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (sniff, wrpcap, conf, IP, IPv6, TCP, UDP, ICMP,
                           ARP, DNS, DNSQR, Raw)
except ImportError:
    print("[!] Scapy is not installed. Run:  pip install scapy")
    sys.exit(1)

# ---------- terminal colours (works on Linux and Windows 10+) ----------
os.system("")  # enables ANSI colour codes in the Windows terminal
C = {
    "TCP": "\033[94m", "HTTP": "\033[93m", "HTTPS": "\033[96m",
    "UDP": "\033[92m", "DNS": "\033[95m", "ICMP": "\033[91m",
    "ARP": "\033[33m", "OTHER": "\033[37m",
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"

# ---------- global counters ----------
stats = Counter()          # protocol -> packet count
src_ips = Counter()        # source IP -> packet count
captured = []              # packets kept only if --output is used
packet_no = 0


def get_protocol(pkt):
    """Return a simple protocol name for the packet."""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        ports = (pkt[TCP].sport, pkt[TCP].dport)
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "HTTPS"
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def get_addresses(pkt):
    """Return (source, destination) as 'ip:port' strings where possible."""
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    else:
        return pkt.src, pkt.dst  # MAC addresses as a fallback

    for layer in (TCP, UDP):
        if pkt.haslayer(layer):
            src += f":{pkt[layer].sport}"
            dst += f":{pkt[layer].dport}"
            break
    return src, dst


def payload_preview(pkt, limit=70):
    """Return the first bytes of the payload as readable text."""
    if not pkt.haslayer(Raw):
        return None
    data = bytes(pkt[Raw].load)[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return text + ("..." if len(pkt[Raw].load) > limit else "")


def extra_info(pkt, proto):
    """Protocol-specific details shown under the main line."""
    if proto == "DNS" and pkt.haslayer(DNSQR):
        name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        kind = "Response" if pkt[DNS].qr == 1 else "Query"
        return f"DNS {kind}: {name}"
    if proto == "ARP":
        op = "Who has" if pkt[ARP].op == 1 else "Reply:"
        return f"ARP {op} {pkt[ARP].pdst}? (from {pkt[ARP].psrc} / {pkt[ARP].hwsrc})"
    if proto == "ICMP":
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable",
                 11: "Time Exceeded"}
        return f"ICMP {types.get(pkt[ICMP].type, 'Type ' + str(pkt[ICMP].type))}"
    return None


def process_packet(pkt):
    """Called by Scapy for every captured packet."""
    global packet_no
    packet_no += 1

    proto = get_protocol(pkt)
    src, dst = get_addresses(pkt)
    stats[proto] += 1
    src_ips[src.rsplit(":", 1)[0] if pkt.haslayer(IP) else src] += 1
    if captured is not None:
        captured.append(pkt)

    time_now = datetime.now().strftime("%H:%M:%S")
    flags = f" flags={pkt[TCP].flags}" if pkt.haslayer(TCP) else ""
    colour = C.get(proto, "")

    print(f"{DIM}[{packet_no:04d}] {time_now}{RESET}  "
          f"{colour}{BOLD}{proto:<6}{RESET} "
          f"{src:<22} -> {dst:<22} len={len(pkt)}{flags}")

    info = extra_info(pkt, proto)
    if info:
        print(f"        {colour}{info}{RESET}")
    data = payload_preview(pkt)
    if data:
        print(f"        Payload: {data}")


def print_summary():
    total = sum(stats.values())
    print(f"\n{BOLD}{'=' * 60}\n  CAPTURE SUMMARY\n{'=' * 60}{RESET}")
    print(f"  Total packets captured : {total}\n")
    print(f"  {'Protocol':<10}{'Packets':>8}{'Share':>10}")
    print(f"  {'-' * 28}")
    for proto, count in stats.most_common():
        share = (count / total * 100) if total else 0
        print(f"  {C.get(proto, '')}{proto:<10}{RESET}{count:>8}{share:>9.1f}%")
    print(f"\n  Top 5 source addresses:")
    for ip, count in src_ips.most_common(5):
        print(f"    {ip:<40} {count} packets")
    print(f"{BOLD}{'=' * 60}{RESET}")


def main():
    global captured
    parser = argparse.ArgumentParser(description="Basic Network Sniffer using Scapy")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None,
                        help='BPF filter, e.g. "tcp", "icmp", "udp port 53", "host 8.8.8.8"')
    parser.add_argument("-o", "--output", help="Save captured packets to a .pcap file")
    parser.add_argument("--list", action="store_true", help="List network interfaces and exit")
    args = parser.parse_args()

    if args.list:
        print(conf.ifaces)
        return

    if not args.output:
        captured = None

    iface = args.iface or conf.iface
    print(f"{BOLD}{'=' * 60}\n  BASIC NETWORK SNIFFER  (Scapy)\n{'=' * 60}{RESET}")
    print(f"  Interface : {iface}")
    print(f"  Filter    : {args.filter or 'none (all traffic)'}")
    print(f"  Count     : {args.count or 'unlimited (press Ctrl+C to stop)'}")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'=' * 60}{RESET}\n")

    try:
        sniff(iface=args.iface, filter=args.filter, prn=process_packet,
              count=args.count, store=False)
    except PermissionError:
        print("[!] Permission denied. Run as Administrator (Windows) or with sudo (Linux).")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    print_summary()
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"  Saved {len(captured)} packets to {args.output}\n")


if __name__ == "__main__":
    main()
