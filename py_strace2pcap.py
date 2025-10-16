#!/usr/bin/env python3
""" tool for converting strace format to synthetic pcap
    1) pip3 install scapy
    2) strace -f -s65535 -o /tmp/straceSample -ttt -T -yy command
    3) py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
    4) wireshark file_to_store.pcap """

import inspect

from scapy.all import RawPcapWriter

from strace_parser import StraceParser
from strace_parser_2_packet import StraceParser2Packet
from unix_tcp_synth import UnixTCPManager


def _write_record(pktdump, record):
    """Write a raw packet record, handling scapy compatibility quirks."""

    if not getattr(pktdump, "header_present", False):
        pktdump._write_header(None)
    kwargs = {
        "sec": record.ts_sec,
        "usec": record.ts_usec,
        "caplen": len(record.data),
        "wirelen": len(record.data),
    }
    try:
        pktdump.write_packet(record.data, **kwargs)
    except TypeError:
        # Older scapy releases expect the linktype positional argument.
        params = inspect.signature(pktdump._write_packet).parameters
        if "linktype" in params:
            kwargs["linktype"] = getattr(pktdump, "linktype", None)
        pktdump._write_packet(record.data, **kwargs)




def _iterate_events(strace_parser, stream):
    for line in stream:
        event = strace_parser.process(line)
        while event:
            yield event
            if strace_parser.has_split_cache():
                event = strace_parser.get_split_cache()
            else:
                break


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Convert strace output to PCAP')
    parser.add_argument('pcap_filename')
    parser.add_argument('--unix-only', action='store_true',
                        help='Emit only AF_UNIX events synthesised as TCP')
    parser.add_argument('--unix-to-tcp', dest='unix_to_tcp', action='store_true',
                        help='Synthesize TCP flows for UNIX stream sockets (default)')
    parser.add_argument('--no-unix-to-tcp', dest='unix_to_tcp', action='store_false',
                        help='Disable UNIX stream TCP synthesis')
    parser.set_defaults(unix_to_tcp=True)
    parser.add_argument('--linktype', choices=['raw', 'ether'], default='raw',
                        help='PCAP link-layer type for AF_INET/AF_INET6 packets')

    args = parser.parse_args()

    if args.unix_only and not args.unix_to_tcp:
        parser.error('--unix-only requires UNIX TCP synthesis to be enabled')

    unix_tcp_enabled = args.unix_to_tcp
    if args.unix_only or unix_tcp_enabled:
        linktype_value = 1
        inet_linktype = 'ether'
    else:
        linktype_value = 101 if args.linktype == 'raw' else 1
        inet_linktype = args.linktype

    pktdump = RawPcapWriter(args.pcap_filename, linktype=linktype_value)

    strace_parser = StraceParser()
    inet_packetizer = None if args.unix_only else StraceParser2Packet(linktype=inet_linktype)
    unix_manager = UnixTCPManager() if unix_tcp_enabled else None

    for event in _iterate_events(strace_parser, sys.stdin):
        if not event:
            continue
        protocol = event.get('protocol')
        if protocol and protocol.startswith('UNIX'):
            if not unix_tcp_enabled:
                continue
            if protocol != 'UNIX-STREAM':
                continue
            for record in unix_manager.handle_event(event):
                _write_record(pktdump, record)
            continue
        if args.unix_only:
            continue
        packet = inet_packetizer.process(event)
        if packet:
            pktdump.write(packet)

    if unix_manager:
        for record in unix_manager.flush():
            _write_record(pktdump, record)
