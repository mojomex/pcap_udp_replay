# PCAP Rewrite & Replay

This tool replays UDP packets from a PCAP file, rewriting the packet headers such that the packets are sent
from the host running the tool to a given destination IP address.
The destination port stays unmodified.
This is useful e.g. when wanting to recreate multi-host communication on one single machine.

Specifically, extracts the UDP payload of each packet in the PCAP (non-UDP packets are dropped)
and sends a new UDP packet to the given `dst_address`. The packets are sent at the same rate they were recorded
in, or slower if the tool cannot keep up with that rate.

The source address is set to the device's IP address on the interface that routes to `dst_address`.
The source port is set to a random free port.

Supported formats: `.pcap`, `.pcapng`

## Setup

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
./replay.py [dst_address] <pcap_file>
```
`dst_address=127.0.0.1` by default.