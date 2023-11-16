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
parser.add_argument("input", help="The PCAP file to read from. Supported formats: .pcap, .pcapng")
parser.add_argument(
    "--dst-address",
    default="127.0.0.1",
    metavar="IP",
    help="The IP address to send packets to (default: 127.0.0.1)",
)
parser.add_argument(
    "-n", "--num-packets", type=int, help="The number of packets to send (default: 0 (all))",
    default=0
)
parser.add_argument(
    "-f", "--filter", help="A Python lambda function to filter packets (default: None)"
)

args = parser.parse_args()
filt = eval(args.filter) if args.filter is not None else lambda _: True

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

n_sent = 0
n_discarded = 0

# Progress bar displays (bytes read) / (total bytes of PCAP file)
n_bytes_total = os.path.getsize(args.input)
prog = tqdm.tqdm(desc="Replaying Packets", total=n_bytes_total, unit='B', unit_scale=True)

file_type = os.path.splitext(args.input)[1]

with open(args.input, "rb") as f:
    if file_type == ".pcap":
        pcap = dpkt.pcap.Reader(f)
    elif file_type == ".pcapng":
        pcap = dpkt.pcapng.Reader(f)
    else:
        print(f"Unknown file type: {file_type}. Expected .pcap or .pcapng.")
        exit(1)

    timestamp_last = None
    t_last = None

    for i, (timestamp_s, buf) in enumerate(pcap):
        if n_sent >= args.num_packets and args.num_packets > 0:
            break
        prog.update(f.tell() - prog.n)
        
        # This automatically discards everything that is not a UDP packet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            udp = ip.data
            payload = udp.data
            dport = udp.dport

            if not filt(eth):
                n_discarded += 1
                continue
        except AttributeError:
            n_discarded += 1
            continue

        # To send packets at the same rate they were recorded in, wait if necessary
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

if args.n == 0:
    prog.update(n_bytes_total - prog.n)
prog.close()
print(f"Read {n_sent + n_discarded} packets, sent {n_sent}, discarded {n_discarded}.")
