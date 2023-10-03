# PCAP Replay

This tool replays UDP packets from PCAP files, rewriting the packet headers such that the packets are sent
from the host running the tool to a given destination IP address.
The destination port stays unmodified.
This is useful e.g. when wanting to recreate multi-host communication on one single machine.

## Setup

```bash
pip3 install -r requirements.txt
```

## Usage

```bash
./replay.py [dst_address] <pcap_file>
```
`dst_address=127.0.0.1` by default.