import struct
import subprocess
import sys

import pytest


def _escape(data: bytes) -> str:
    return ''.join('\\x{:02x}'.format(b) for b in data)


def _read_pcap(path):
    packets = []
    with open(path, 'rb') as fh:
        header = fh.read(24)
        assert len(header) == 24
        magic, v_major, v_minor, tz, sigfigs, snaplen, network = struct.unpack('<IHHIIII', header)
        assert magic == 0xA1B2C3D4
        assert network == 1  # DLT_EN10MB
        while True:
            pkt_hdr = fh.read(16)
            if not pkt_hdr:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_hdr)
            data = fh.read(incl_len)
            assert len(data) == incl_len
            packets.append((ts_sec, ts_usec, data))
    return packets


def _tcp_flags(packet_bytes):
    tcp_offset = 14 + 20
    offset_flags = struct.unpack('!H', packet_bytes[tcp_offset + 12:tcp_offset + 14])[0]
    return offset_flags & 0x01FF


def _tcp_ports(packet_bytes):
    tcp_offset = 14 + 20
    sport, dport = struct.unpack('!HH', packet_bytes[tcp_offset:tcp_offset + 4])
    return sport, dport


@pytest.mark.parametrize('link_flag', [[], ['--linktype', 'ether']])
def test_unix_stream_tcp_synthesis(tmp_path, link_flag):
    pcap_path = tmp_path / 'out.pcap'
    preface = _escape(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
    response = _escape(b'\x00\x00\x12\x01DATA')
    strace_text = '\n'.join([
        f'1234 1760606087.226484 write(54<UNIX-STREAM:[1606248]>, "{preface}", 24) = 24',
        f'1234 1760606087.226700 read(54<UNIX-STREAM:[1606248]>, "{response}", 8) = 8',
        '1234 1760606087.226900 close(54<UNIX-STREAM:[1606248]>) = 0',
        ''
    ])
    cmd = [sys.executable, 'py_strace2pcap.py', '--unix-only', str(pcap_path)] + link_flag
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    assert len(packets) >= 6

    # Handshake packets
    syn_flags = _tcp_flags(packets[0][2])
    synack_flags = _tcp_flags(packets[1][2])
    ack_flags = _tcp_flags(packets[2][2])
    assert syn_flags & 0x02  # SYN
    assert synack_flags & 0x12 == 0x12
    assert ack_flags & 0x10

    # First payload carries the HTTP/2 preface
    payload_packet = packets[3][2]
    payload = payload_packet[14 + 20 + 20:]
    assert payload.startswith(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

    # Next packet is peer response with eight bytes of data
    response_packet = packets[4][2]
    response_payload = response_packet[14 + 20 + 20:]
    assert response_payload == b'\x00\x00\x12\x01DATA'

    sport, dport = _tcp_ports(payload_packet)
    assert dport == 50051
    assert sport != dport

    # Final FIN/ACK sequence present
    fin_flags = _tcp_flags(packets[-2][2])
    final_ack_flags = _tcp_flags(packets[-1][2])
    assert fin_flags & 0x01
    assert final_ack_flags & 0x10
