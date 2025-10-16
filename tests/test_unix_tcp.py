import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unix_tcp_synth import (
    GRPC_HEADERS_FRAME,
    HTTP2_CLIENT_SEED,
    HTTP2_SETTINGS_ACK_FRAME,
)


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
    ihl = (packet_bytes[14] & 0x0F) * 4
    tcp_offset = 14 + ihl
    offset_flags = struct.unpack('!H', packet_bytes[tcp_offset + 12:tcp_offset + 14])[0]
    return offset_flags & 0x01FF


def _tcp_ports(packet_bytes):
    ihl = (packet_bytes[14] & 0x0F) * 4
    tcp_offset = 14 + ihl
    sport, dport = struct.unpack('!HH', packet_bytes[tcp_offset:tcp_offset + 4])
    return sport, dport


def _tcp_payload(packet_bytes):
    ihl = (packet_bytes[14] & 0x0F) * 4
    tcp_offset = 14 + ihl
    data_offset = (packet_bytes[tcp_offset + 12] >> 4) * 4
    return packet_bytes[tcp_offset + data_offset:]


def test_unix_stream_tcp_synthesis_with_coalescing(tmp_path):
    pcap_path = tmp_path / 'out.pcap'
    preface_bytes = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
    extra_bytes = b'HELLO'
    response_bytes = b'RESPONSE'
    preface = _escape(preface_bytes)
    extra = _escape(extra_bytes)
    response = _escape(response_bytes)
    strace_text = '\n'.join([
        f'1234 1760606087.100000 write(54<UNIX-STREAM:[1606248]>, "{preface}", 24) = 24',
        f'1234 1760606087.100150 write(54<UNIX-STREAM:[1606248]>, "{extra}", 5) = 5',
        f'1234 1760606087.100400 read(54<UNIX-STREAM:[1606248]>, "{response}", 8) = 8',
        '1234 1760606087.100800 close(54<UNIX-STREAM:[1606248]>) = 0',
        ''
    ])
    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    assert len(packets) >= 7

    syn_flags = _tcp_flags(packets[0][2])
    synack_flags = _tcp_flags(packets[1][2])
    ack_flags = _tcp_flags(packets[2][2])
    assert syn_flags & 0x02
    assert synack_flags & 0x12 == 0x12
    assert ack_flags & 0x10

    data_packets = [pkt for pkt in packets if _tcp_flags(pkt[2]) & 0x08]
    client_payloads = [
        _tcp_payload(pkt[2])
        for pkt in data_packets
        if _tcp_ports(pkt[2])[1] == 50051
    ]
    assert len(client_payloads) == 1
    assert client_payloads[0] == preface_bytes + extra_bytes

    server_payloads = [
        _tcp_payload(pkt[2])
        for pkt in data_packets
        if _tcp_ports(pkt[2])[0] == 50051
    ]
    assert response_bytes in server_payloads

    sport, dport = _tcp_ports(data_packets[0][2])
    assert dport == 50051
    assert sport != dport

    fin_flags = _tcp_flags(packets[-2][2])
    final_ack_flags = _tcp_flags(packets[-1][2])
    assert fin_flags & 0x01
    assert final_ack_flags & 0x10


def test_unix_stream_seed_http2(tmp_path):
    pcap_path = tmp_path / 'seed_http2.pcap'
    payload_bytes = b'\x00\x00\x12\x01DATA'
    payload = _escape(payload_bytes)
    strace_text = '\n'.join([
        f'4321 1760606087.200000 read(77<UNIX-STREAM:[42]>, "{payload}", 8) = 8',
        '4321 1760606087.200400 close(77<UNIX-STREAM:[42]>) = 0',
        ''
    ])
    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        '--seed-http2',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & 0x08]

    assert any(pl.startswith(HTTP2_CLIENT_SEED) for pl in payloads)
    assert HTTP2_SETTINGS_ACK_FRAME in payloads
    assert payload_bytes in payloads


def test_unix_stream_seed_grpc(tmp_path):
    pcap_path = tmp_path / 'seed_grpc.pcap'
    payload_bytes = b'\x01\x02'
    payload = _escape(payload_bytes)
    strace_text = '\n'.join([
        f'9999 1760606087.300000 read(12<UNIX-STREAM:[777]>, "{payload}", 2) = 2',
        '9999 1760606087.300400 close(12<UNIX-STREAM:[777]>) = 0',
        ''
    ])
    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        '--seed-http2',
        '--seed-grpc',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & 0x08]

    assert any(frame.startswith(GRPC_HEADERS_FRAME[:9]) for frame in payloads)
    assert payload_bytes in payloads
