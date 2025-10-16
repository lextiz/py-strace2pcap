#!/usr/bin/env python3
""" tool for converting strace format to synthetic pcap
    1) pip3 install scapy
    2) strace -f -s65535 -o /tmp/straceSample -ttt -T -yy command
    3) py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
    4) wireshark file_to_store.pcap """


from scapy.all import RawPcapWriter
from strace_parser import StraceParser
from strace_parser_2_packet import StraceParser2Packet
from process_cascade import ProcessCascade
from pcap_synth import UnixSynthConfig


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Convert strace output to PCAP')
    parser.add_argument('pcap_filename')
    parser.add_argument('--unix-to-tcp', dest='unix_to_tcp', action='store_true',
                        help='Enable AF_UNIX to TCP synthesis (default)')
    parser.add_argument('--no-unix-to-tcp', dest='unix_to_tcp', action='store_false',
                        help='Disable AF_UNIX to TCP synthesis')
    parser.set_defaults(unix_to_tcp=True)
    parser.add_argument('--unix-base-ip-a', default='10.0.0.1',
                        help='Base IPv4 address for synthetic AF_UNIX side A')
    parser.add_argument('--unix-base-ip-b', default='10.0.1.1',
                        help='Base IPv4 address for synthetic AF_UNIX side B')
    parser.add_argument('--unix-base-sport', type=int, default=30000,
                        help='Base TCP/UDP source port for AF_UNIX synthesis')
    parser.add_argument('--unix-base-dport', type=int, default=40000,
                        help='Base TCP/UDP destination port for AF_UNIX synthesis')
    parser.add_argument('--linktype', choices=['raw', 'ether'], default='raw',
                        help='PCAP link-layer type (default raw)')

    args = parser.parse_args()

    unix_config = UnixSynthConfig(
        enable=args.unix_to_tcp,
        base_ip_a=args.unix_base_ip_a,
        base_ip_b=args.unix_base_ip_b,
        base_sport=args.unix_base_sport,
        base_dport=args.unix_base_dport,
        linktype=args.linktype,
    )

    linktype_value = 101 if args.linktype == 'raw' else 1
    pktdump = RawPcapWriter(args.pcap_filename, linktype=linktype_value)

    packet_processor = lambda: StraceParser2Packet(
        unix_config=unix_config, linktype=args.linktype)

    for packet in ProcessCascade(
            packet_processor, ProcessCascade(StraceParser, sys.stdin)):
        if packet:
            pktdump.write(packet)
