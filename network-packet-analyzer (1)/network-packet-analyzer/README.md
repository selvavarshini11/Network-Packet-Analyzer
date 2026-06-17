# Network Packet Analyzer

A lightweight, real-time network packet capture and analysis tool built with **Python + Scapy**. Designed for networking enthusiasts and aspiring network engineers who want hands-on experience with TCP/IP traffic at the packet level.

> Pair it with the [Live Web Dashboard](https://github.com/your-username/network-packet-analyzer#dashboard) for a visual, real-time packet monitoring experience.

---

## Features

- **Live packet capture** on any network interface
- **Protocol filtering** — TCP, UDP, DNS, HTTPS, HTTP, ICMP, ARP
- **Real-time display** of source/destination IPs, ports, flags, and payload lengths
- **Capture statistics** — total packets, bytes, average size, protocol distribution
- **Export to `.pcap`** for deep-dive analysis in Wireshark
- **Web dashboard** — React-based live visualization (see below)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/network-packet-analyzer.git
cd network-packet-analyzer

# Install dependencies
pip install -r requirements.txt
```

> **Requirements:** Python 3.8+, [Scapy](https://scapy.net/), root/admin privileges for raw socket capture.

---

## Usage

### Basic capture
```bash
sudo python packet_analyzer.py -i eth0
```

### Filter by protocol
```bash
sudo python packet_analyzer.py -i wlan0 -p DNS -c 20
```

### Save to pcap
```bash
sudo python packet_analyzer.py -i eth0 -p TCP -o capture.pcap
```

### List interfaces
```bash
python packet_analyzer.py --list-interfaces
```

---

## Sample Output

```
====================================================================================================
No.   Time        Source            Destination       Proto   Len     Info
----------------------------------------------------------------------------------------------------
1     14:32:01    192.168.1.10      142.250.190.78    DNS     78      Query: google.com | ID=12345
2     14:32:01    142.250.190.78    192.168.1.10      DNS     145     Response A 142.250.190.78
3     14:32:02    192.168.1.10      142.250.190.78    HTTPS   66      Flags=S | Len=0
4     14:32:02    142.250.190.78    192.168.1.10      HTTPS   66      Flags=SA | Len=0
5     14:32:02    192.168.1.10      142.250.190.78    HTTPS   573     Flags=PA | Len=507
6     14:32:02    142.250.190.78    192.168.1.10      HTTPS   1514    Flags=PA | Len=1448
7     14:32:03    192.168.1.10      1.1.1.1           ICMP    98      Echo (ping) request
8     14:32:03    1.1.1.1           192.168.1.10      ICMP    98      Echo (ping) reply
9     14:32:04    192.168.1.24      192.168.1.1       ARP     60      Who-has 192.168.1.1? Tell 192.168.1.24
10    14:32:04    192.168.1.1       192.168.1.24      ARP     42      192.168.1.1 is at aa:bb:cc:dd:ee:ff

============================================================
Capture Summary
  Duration     : 3.21 seconds
  Total packets: 15
  Total bytes  : 4,287
  Average size : 285.8 bytes
  Protocol distribution:
    HTTPS        2 packets ( 13.3%)
    TCP          5 packets ( 33.3%)
    DNS          2 packets ( 13.3%)
    ICMP         2 packets ( 13.3%)
    ARP          2 packets ( 13.3%)
    UDP          1 packets (  6.7%)
    HTTP         1 packets (  6.7%)
============================================================
```

---

## Dashboard

This repository also includes a **React web dashboard** built with TanStack Start, Tailwind CSS, and Recharts. It visualizes live (or simulated) packet data with:

- Real-time throughput charts
- Protocol distribution pie charts
- Top talkers bar graphs
- Scrollable, filterable packet table
- Pause / resume / clear controls

### Running the dashboard

```bash
cd dashboard
bun install
bun run dev
```

> The dashboard currently uses simulated traffic for demo purposes. For real capture data, pipe the Python CLI output into the dashboard backend or export `.pcap` files for upload.

---

## Project Structure

```
network-packet-analyzer/
├── packet_analyzer.py    # Main Python CLI tool
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── .gitignore            # Ignore pcap/venv/cache files
└── dashboard/            # React web dashboard (optional)
    ├── src/
    │   └── routes/
    │       └── index.tsx
    ├── package.json
    └── ...
```

---

## Why this project?

Cisco is a networking company at its core — demonstrating hands-on packet-level TCP/IP knowledge signals that you're serious about networking, not just web development. Even a basic packet analyzer is impressive for a fresher and shows:

- Low-level networking concepts (OSI layers, protocols, flags)
- Python proficiency + external library integration (Scapy)
- CLI tool design, argument parsing, and error handling
- Optional: full-stack web visualization skills

---

## License

MIT License — feel free to use, modify, and share.
