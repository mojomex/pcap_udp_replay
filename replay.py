#!/usr/bin/python3

import socket
import dpkt
import time
import argparse
import os
import tqdm

parser = argparse.ArgumentParser(
    description="Replay a PCAP file containing UDP packets while rewriting the target IP address"
)
parser.add_argument("input", help="The PCAP file to read from")
parser.add_argument(
    "--dst-address",
    default="127.0.0.1",
    metavar="IP",
    help="The IP address to send packets to (default: 127.0.0.1)",
)

args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

n_sent = 0
n_discarded = 0

n_bytes_total = os.path.getsize(args.input)
prog = tqdm.tqdm(desc="Replaying PCAP", total=n_bytes_total, unit='B', unit_scale=True)
with open(args.input, "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    timestamp_last = None
    t_last = None

    for i, (timestamp_s, buf) in enumerate(pcap):
        prog.update(len(buf))
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data
            payload = udp.data
            dport = udp.dport
        except AttributeError:
            n_discarded += 1
            continue

        t_now = time.time()
        if timestamp_last is None:
            wait_s = 0
        else:
            wait_s = max(0, timestamp_s - timestamp_last - (t_now - t_last))

        timestamp_last = timestamp_s
        t_last = t_now

        if wait_s > 0:
            time.sleep(wait_s)

        sock.sendto(payload, (args.dst_address, dport))
        n_sent += 1

prog.close()
print(f"Read {n_sent + n_discarded} packets, sent {n_sent}, discarded {n_discarded}.")
