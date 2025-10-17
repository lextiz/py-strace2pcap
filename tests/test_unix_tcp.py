import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unix_tcp_synth import HTTP2_CLIENT_SEED, HTTP2_SETTINGS_ACK_FRAME, build_grpc_headers_frame


TCP_FLAG_PSH = 0x08
TCP_FLAG_FIN = 0x01


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


def _tcp_checksum(packet_bytes):
    ihl = (packet_bytes[14] & 0x0F) * 4
    tcp_offset = 14 + ihl
    return struct.unpack('!H', packet_bytes[tcp_offset + 16:tcp_offset + 18])[0]


def test_http2_frame_alignment_and_close(tmp_path):
    pcap_path = tmp_path / 'out.pcap'
    client_frame = b'\x00\x00\x05\x00\x01\x00\x00\x00\x01HELLO'
    server_frame = b'\x00\x00\x03\x00\x01\x00\x00\x00\x01ACK'

    first_chunk = _escape(client_frame[:5])
    second_chunk = _escape(client_frame[5:])
    server_chunk = _escape(server_frame)

    strace_text = '\n'.join([
        f'1234 1760606087.100000 write(54<UNIX-STREAM:[1606248]>, "{first_chunk}", 5) = 5',
        f'1234 1760606087.100050 write(54<UNIX-STREAM:[1606248]>, "{second_chunk}", {len(client_frame) - 5}) = {len(client_frame) - 5}',
        f'1234 1760606087.100400 read(54<UNIX-STREAM:[1606248]>, "{server_chunk}", {len(server_frame)}) = {len(server_frame)}',
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
    assert len(packets) >= 6

    data_packets = [pkt for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]

    client_payloads = [
        _tcp_payload(pkt[2])
        for pkt in data_packets
        if _tcp_ports(pkt[2])[1] == 50051
    ]
    assert client_payloads == [client_frame]
    assert _tcp_checksum(data_packets[0][2]) != 0

    server_payloads = [
        _tcp_payload(pkt[2])
        for pkt in data_packets
        if _tcp_ports(pkt[2])[0] == 50051
    ]
    assert server_frame in server_payloads

    fin_packets = [pkt for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_FIN]
    assert fin_packets, 'FIN not emitted'


def test_unix_stream_seed_http2(tmp_path):
    pcap_path = tmp_path / 'seed_http2.pcap'
    server_frame = b'\x00\x00\x02\x00\x00\x00\x00\x00\x01OK'
    payload = _escape(server_frame)

    strace_text = '\n'.join([
        f'4321 1760606087.200000 read(77<UNIX-STREAM:[42]>, "{payload}", {len(server_frame)}) = {len(server_frame)}',
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
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]

    assert HTTP2_CLIENT_SEED in payloads
    assert HTTP2_SETTINGS_ACK_FRAME in payloads
    assert server_frame in payloads


def test_unix_stream_seed_grpc(tmp_path):
    pcap_path = tmp_path / 'seed_grpc.pcap'
    server_frame = b'\x00\x00\x01\x00\x00\x00\x00\x00\x01!'
    payload = _escape(server_frame)

    strace_text = '\n'.join([
        f'9999 1760606087.300000 read(12<UNIX-STREAM:[777]>, "{payload}", {len(server_frame)}) = {len(server_frame)}',
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
        'force',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]

    expected_seed = build_grpc_headers_frame()
    assert any(payload == expected_seed for payload in payloads)
    assert server_frame in payloads


def test_residual_bytes_flushed_on_close(tmp_path):
    pcap_path = tmp_path / 'residual.pcap'
    payload = b'PARTIAL'
    escaped = _escape(payload)

    strace_text = '\n'.join([
        f'5555 1760606087.400000 write(22<UNIX-STREAM:[888]>, "{escaped}", {len(payload)}) = {len(payload)}',
        '5555 1760606087.400400 close(22<UNIX-STREAM:[888]>) = 0',
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
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]
    assert payload in payloads


def test_no_checksum_flag(tmp_path):
    pcap_path = tmp_path / 'no_checksum.pcap'
    frame = b'\x00\x00\x01\x00\x01\x00\x00\x00\x01A'
    escaped = _escape(frame)

    strace_text = '\n'.join([
        f'1111 1760606087.500000 write(5<UNIX-STREAM:[111]>, "{escaped}", {len(frame)}) = {len(frame)}',
        '1111 1760606087.500400 close(5<UNIX-STREAM:[111]>) = 0',
        ''
    ])

    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        '--no-checksum',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    data_packets = [pkt for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]
    assert data_packets, 'expected data packet'
    assert _tcp_checksum(data_packets[0][2]) == 0


def test_seed_grpc_auto_detects_data_frames(tmp_path):
    pcap_path = tmp_path / 'seed_grpc_auto.pcap'
    grpc_data = b'\x00\x00\x05\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00'
    escaped = _escape(grpc_data)

    strace_text = '\n'.join([
        f'7777 1760606087.600000 write(31<UNIX-STREAM:[4242]>, "{escaped}", {len(grpc_data)}) = {len(grpc_data)}',
        '7777 1760606087.600400 close(31<UNIX-STREAM:[4242]>) = 0',
        ''
    ])

    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        '--seed-http2',
        '--seed-grpc',
        'auto',
        str(pcap_path),
    ]
    subprocess.run(cmd, input=strace_text, text=True, check=True)

    packets = _read_pcap(pcap_path)
    payloads = [_tcp_payload(pkt[2]) for pkt in packets if _tcp_flags(pkt[2]) & TCP_FLAG_PSH]
    expected_seed = build_grpc_headers_frame()
    assert expected_seed in payloads
    assert grpc_data in payloads
