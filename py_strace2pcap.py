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
from unix_user0 import UnixUser0Emitter


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Convert strace output to PCAP')
    parser.add_argument('pcap_filename')
    parser.add_argument('--unix-only', action='store_true',
                        help='Emit only AF_UNIX events using USER0 frames (DLT 147)')
    parser.add_argument('--include-unix-paths', dest='include_unix_paths',
                        action='store_true', help='Include AF_UNIX path metadata')
    parser.add_argument('--no-include-unix-paths', dest='include_unix_paths',
                        action='store_false', help='Omit AF_UNIX path metadata')
    parser.set_defaults(include_unix_paths=True)
    parser.add_argument('--linktype', choices=['raw', 'ether'], default='raw',
                        help='PCAP link-layer type for AF_INET/AF_INET6 packets')

    args = parser.parse_args()

    if args.unix_only:
        pktdump = RawPcapWriter(args.pcap_filename, linktype=147)
        packet_processor = lambda: UnixUser0Emitter(
            include_paths=args.include_unix_paths)
    else:
        linktype_value = 101 if args.linktype == 'raw' else 1
        pktdump = RawPcapWriter(args.pcap_filename, linktype=linktype_value)
        packet_processor = lambda: StraceParser2Packet(linktype=args.linktype)

    for packet in ProcessCascade(
            packet_processor, ProcessCascade(StraceParser, sys.stdin)):
        if packet:
            pktdump.write(packet)
