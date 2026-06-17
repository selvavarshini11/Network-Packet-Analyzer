#!/usr/bin/env python3
"""
Network Packet Analyzer
A lightweight, real-time packet capture and analysis tool built with Python + Scapy.

Features:
- Live packet capture on any network interface
- Protocol filtering (TCP, UDP, DNS, HTTPS, HTTP, ICMP, ARP)
- Source / destination IP & port extraction
- Packet length, flags, and info summaries
- Real-time statistics (total packets, bytes, average size, protocol distribution)
- Export captures to .pcap for Wireshark analysis

Author: Cisco Networking Enthusiast
"""

import argparse
import os
import signal
import sys
import time
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Scapy import with graceful fallback
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        ICMP,
        IP,
        TCP,
        UDP,
        conf,
        get_if_list,
        rdpcap,
        sniff,
        wrpcap,
    )
except ImportError:
    print("ERROR: Scapy is required. Install it with: pip install scapy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ANSI colours (optional, for terminal output)
# ---------------------------------------------------------------------------
COLORS = {
    "TCP": "\033[94m",
    "UDP": "\033[95m",
    "DNS": "\033[92m",
    "HTTPS": "\033[93m",
    "HTTP": "\033[91m",
    "ICMP": "\033[96m",
    "ARP": "\033[90m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}

USE_COLOR = sys.stdout.isatty()


def c(name: str, text: str) -> str:
    return f"{COLORS.get(name, '')}{text}{COLORS['RESET']}" if USE_COLOR else text


# ---------------------------------------------------------------------------
# Packet metadata extraction
# ---------------------------------------------------------------------------
def classify_packet(pkt):
    """Return a dict with human-readable fields for a given Scapy packet."""
    info = {
        "protocol": "OTHER",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(pkt),
        "info": "",
    }

    if IP in pkt:
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst

        if TCP in pkt:
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            flags = pkt[TCP].sprintf("%TCP.flags%")
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                info["protocol"] = "HTTPS"
                info["info"] = f"{c('HTTPS', 'HTTPS')} | Flags={flags} | Len={len(pkt[TCP].payload)}"
            elif pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                info["protocol"] = "HTTP"
                info["info"] = f"{c('HTTP', 'HTTP')} | Flags={flags} | Len={len(pkt[TCP].payload)}"
            else:
                info["protocol"] = "TCP"
                info["info"] = f"Flags={flags} | Seq={pkt[TCP].seq} | Ack={pkt[TCP].ack}"

        elif UDP in pkt:
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            if DNS in pkt:
                info["protocol"] = "DNS"
                qname = ""
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
                info["info"] = f"Query: {qname} | ID={pkt[DNS].id}"
            else:
                info["protocol"] = "UDP"
                info["info"] = f"Len={len(pkt[UDP].payload)}"

        elif ICMP in pkt:
            info["protocol"] = "ICMP"
            icmp_type = pkt[ICMP].type
            type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
            info["info"] = type_map.get(icmp_type, f"Type={icmp_type}")

    elif ARP in pkt:
        info["protocol"] = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["dst_ip"] = pkt[ARP].pdst
        op = "Who-has" if pkt[ARP].op == 1 else "Is-at" if pkt[ARP].op == 2 else f"Op={pkt[ARP].op}"
        info["info"] = f"{op} {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"

    return info


# ---------------------------------------------------------------------------
# Printing helpers
# ---------------------------------------------------------------------------
def print_header():
    print("\n" + "=" * 100)
    print(f"{'No.':<6}{'Time':<12}{'Source':<18}{'Destination':<18}{'Proto':<8}{'Len':<8}{'Info'}")
    print("-" * 100)


def print_packet_row(idx, meta):
    proto = meta["protocol"]
    src = meta["src_ip"] or ""
    dst = meta["dst_ip"] or ""
    t = time.strftime("%H:%M:%S")
    print(
        f"{idx:<6}{t:<12}{src:<18}{dst:<18}{c(proto, proto):<8}"
        f"{meta['length']:<8}{meta['info']}"
    )


def print_summary(start, packets_meta):
    total = len(packets_meta)
    if total == 0:
        return
    duration = time.time() - start
    total_bytes = sum(m["length"] for m in packets_meta)
    avg = total_bytes / total
    counts = Counter(m["protocol"] for m in packets_meta)
    print("\n" + "=" * 60)
    print(c("BOLD", "Capture Summary"))
    print(f"  Duration     : {duration:.2f} seconds")
    print(f"  Total packets: {total}")
    print(f"  Total bytes  : {total_bytes:,}")
    print(f"  Average size : {avg:.1f} bytes")
    print("  Protocol distribution:")
    for proto, cnt in counts.most_common():
        pct = cnt / total * 100
        print(f"    {c(proto, proto):<10} {cnt:>5} packets ({pct:>5.1f}%)")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Main capture logic
# ---------------------------------------------------------------------------
class PacketCapture:
    def __init__(self, interface, protocol_filter, count, output_pcap):
        self.interface = interface
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.count = count
        self.output_pcap = output_pcap
        self.packets = []
        self.meta_list = []
        self.start_time = time.time()
        self.idx = 0
        self._shutdown = False

        signal.signal(signal.SIGINT, self._sigint_handler)

    def _sigint_handler(self, signum, frame):
        print("\n[INFO] Stopping capture...")
        self._shutdown = True

    def _packet_handler(self, pkt):
        if self._shutdown:
            return True  # Stop sniffing

        meta = classify_packet(pkt)
        if self.protocol_filter and meta["protocol"] != self.protocol_filter:
            return False  # Continue sniffing, skip this packet

        self.idx += 1
        self.packets.append(pkt)
        self.meta_list.append(meta)
        print_packet_row(self.idx, meta)

        if self.count and self.idx >= self.count:
            return True
        return False

    def run(self):
        print(f"[INFO] Starting capture on {self.interface}...")
        if self.protocol_filter:
            print(f"[INFO] Filtering by protocol: {self.protocol_filter}")
        if self.count:
            print(f"[INFO] Stopping after {self.count} packets")

        print_header()

        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda pkt: self._shutdown or (self.count and self.idx >= self.count),
            )
        except PermissionError:
            print("\n[ERROR] Permission denied. Run with sudo / administrator privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[ERROR] {e}")
            sys.exit(1)
        finally:
            print_summary(self.start_time, self.meta_list)
            if self.output_pcap and self.packets:
                wrpcap(self.output_pcap, self.packets)
                print(f"[INFO] Saved {len(self.packets)} packets to {self.output_pcap}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def get_parser():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer — Live capture and protocol analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python packet_analyzer.py -i eth0
  sudo python packet_analyzer.py -i wlan0 -p DNS -c 20
  sudo python packet_analyzer.py -i eth0 -p TCP -o capture.pcap
  python packet_analyzer.py --list-interfaces
        """,
    )
    parser.add_argument("-i", "--interface", default=None, help="Network interface to capture on")
    parser.add_argument(
        "-p", "--protocol",
        choices=["TCP", "UDP", "DNS", "HTTPS", "HTTP", "ICMP", "ARP"],
        default=None,
        help="Filter by protocol",
    )
    parser.add_argument("-c", "--count", type=int, default=None, help="Stop after N packets")
    parser.add_argument("-o", "--output", default=None, help="Save captured packets to .pcap file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = get_parser()
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(0)

    if not args.interface:
        print("ERROR: Network interface is required. Use -i or --interface.")
        print("       Run with --list-interfaces to see available options.")
        sys.exit(1)

    # Verify root / admin
    if os.name != "nt" and os.geteuid() != 0:
        print("WARNING: Packet capture usually requires root privileges. Try: sudo python packet_analyzer.py ...")

    capture = PacketCapture(
        interface=args.interface,
        protocol_filter=args.protocol,
        count=args.count,
        output_pcap=args.output,
    )
    capture.run()


if __name__ == "__main__":
    main()
