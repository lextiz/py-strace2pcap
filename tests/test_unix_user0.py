import struct
import subprocess
import uuid
from pathlib import Path

from scapy.all import rdpcap, TCP

SCRIPT = Path(__file__).resolve().parents[1] / "py_strace2pcap.py"


def run_converter(tmp_path, trace, args=None):
    output = tmp_path / f"out_{uuid.uuid4().hex}.pcap"
    cmd = ["python3", str(SCRIPT)]
    if args:
        cmd.extend(args)
    cmd.append(str(output))
    subprocess.run(cmd, input=trace.encode(), check=True)
    return output


def read_pcap(path):
    data = path.read_bytes()
    if len(data) < 24:
        raise AssertionError("pcap too small")
    network = struct.unpack_from("<I", data, 20)[0]
    records = []
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", data, offset)
        start = offset + 16
        end = start + incl_len
        payload = data[start:end]
        records.append((ts_sec, ts_usec, payload))
        offset = end
    return network, records


def parse_uxso(payload):
    header = struct.unpack_from("<4sBBBBIIIII", payload, 0)
    magic, version, sock_type, direction, flags, pid, fd, inode, stream_id, payload_len = header
    cursor = 28
    path = None
    peer_path = None
    if flags & 0x01:
        end = payload.index(b"\x00", cursor)
        path = payload[cursor:end].decode()
        cursor = end + 1
    if flags & 0x02:
        end = payload.index(b"\x00", cursor)
        peer_path = payload[cursor:end].decode()
        cursor = end + 1
    data = payload[cursor:cursor + payload_len]
    return {
        "magic": magic,
        "version": version,
        "sock_type": sock_type,
        "direction": direction,
        "flags": flags,
        "pid": pid,
        "fd": fd,
        "inode": inode,
        "stream_id": stream_id,
        "payload": data,
        "path": path,
        "peer_path": peer_path,
    }


def test_unix_stream_user0_records(tmp_path):
    trace = """\
1234  1760606087.100000 socket(AF_UNIX, SOCK_STREAM, 0) = 54<UNIX:[1606248]>
1234  1760606087.226484 write(54<UNIX-STREAM:[1606248]>, \"\\x41\\x42\\x43\", 3) = 3
1234  1760606087.226700 read(54<UNIX-STREAM:[1606248]>, \"\\x44\\x45\\x46\", 3) = 3
"""
    pcap_path = run_converter(tmp_path, trace, args=["--unix-only"])

    network, records = read_pcap(pcap_path)
    assert network == 147
    assert len(records) == 2

    first = parse_uxso(records[0][2])
    assert first["magic"] == b"UXSO"
    assert first["version"] == 1
    assert first["sock_type"] == 1
    assert first["direction"] == 1
    assert first["inode"] == 1606248
    assert first["payload"] == b"ABC"

    second = parse_uxso(records[1][2])
    assert second["direction"] == 2
    assert second["stream_id"] == first["stream_id"]
    assert second["payload"] == b"DEF"


def test_unix_paths_toggle(tmp_path):
    trace = """\
2000  1700000000.000100 socket(AF_UNIX, SOCK_STREAM, 0) = 5<UNIX:[555]>
2000  1700000000.000200 bind(5<UNIX-STREAM:[555]>, {sa_family=AF_UNIX, sun_path=\"/tmp/test.sock\"}, 110) = 0
2000  1700000000.000300 write(5<UNIX-STREAM:[555]>, \"\\x58\", 1) = 1
"""
    pcap_with_paths = run_converter(tmp_path, trace, args=["--unix-only"])
    pcap_without_paths = run_converter(tmp_path, trace, args=["--unix-only", "--no-include-unix-paths"])

    _, with_records = read_pcap(pcap_with_paths)
    _, without_records = read_pcap(pcap_without_paths)

    with_header = parse_uxso(with_records[0][2])
    assert with_header["flags"] & 0x01
    assert with_header["path"] == "/tmp/test.sock"

    without_header = parse_uxso(without_records[0][2])
    assert without_header["flags"] == 0
    assert without_header["path"] is None


def test_linktype_ether_preserves_inet_metadata(tmp_path):
    trace = """\
1000  1700000000.000000 write(5<TCP:[1]>, \"\\x41\\x42\", 2) = 2
"""
    pcap_path = run_converter(tmp_path, trace, args=["--linktype", "ether"])

    network, records = read_pcap(pcap_path)
    assert network == 1

    packets = rdpcap(str(pcap_path))
    assert packets[0].haslayer(TCP)
    assert bytes(packets[0][TCP].payload) == b"AB"
