import subprocess
from pathlib import Path

from scapy.all import rdpcap, TCP, UDP

SCRIPT = Path(__file__).resolve().parents[1] / "py_strace2pcap.py"


def run_converter(tmp_path, trace, args=None):
    output = tmp_path / "out.pcap"
    cmd = ["python3", str(SCRIPT)]
    if args:
        cmd.extend(args)
    cmd.append(str(output))
    subprocess.run(cmd, input=trace.encode(), check=True)
    return output


def capinfos_lines(pcap_path):
    result = subprocess.run(["capinfos", str(pcap_path)], capture_output=True, check=True, text=True)
    return result.stdout.splitlines()


def test_unix_stream_synthesizes_tcp(tmp_path):
    trace = """\
1234  1760606087.226400 socket(AF_UNIX, SOCK_STREAM, 0) = 54<UNIX:[1606248]>
1234  1760606087.226484 write(54<UNIX-STREAM:[1606248]>, \"\\x50\\x52\\x49\\x20\\x2a\\x20\\x48\\x54\\x54\\x50\\x2f\\x32\\x2e\\x30\\x0d\\x0a\\x0d\\x0a\\x53\\x4d\\x0d\\x0a\\x0d\\x0a\", 24) = 24
1234  1760606087.226700 read(54<UNIX-STREAM:[1606248]>, \"\\x00\\x00\\x12\\x01\", 4) = 4
1234  1760606087.226900 close(54<UNIX-STREAM:[1606248]>) = 0
"""
    pcap_path = run_converter(tmp_path, trace)

    lines = capinfos_lines(pcap_path)
    assert any("Raw IP" in line for line in lines)

    packets = rdpcap(str(pcap_path))
    # SYN, SYN/ACK, ACK, data out, ACK, data in, ACK, FIN, ACK
    assert len(packets) == 9
    assert packets[0].haslayer(TCP)
    assert packets[0][TCP].flags & 0x02  # SYN
    assert packets[1][TCP].flags & 0x12  # SYN-ACK
    # ensure HTTP/2 preface is present in payload of data packet
    assert b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" in bytes(packets[3][TCP].payload)


def test_unix_dgram_synthesizes_udp(tmp_path):
    trace = """\
4321  1760606088.000000 sendto(3<UNIX-DGRAM:[2600]>, \"\\x68\\x69\", 2, 0, NULL, 0) = 2
4321  1760606088.100000 recvfrom(3<UNIX-DGRAM:[2600]>, \"\\x6f\\x6b\", 2, 0, NULL, NULL) = 2
"""
    pcap_path = run_converter(tmp_path, trace)

    lines = capinfos_lines(pcap_path)
    assert any(line.strip().endswith("2") and "Number of packets" in line for line in lines)

    packets = rdpcap(str(pcap_path))
    assert packets[0].haslayer(UDP)
    assert bytes(packets[0][UDP].payload) == b"hi"
    assert bytes(packets[1][UDP].payload) == b"ok"


def test_linktype_ether_preserves_inet_metadata(tmp_path):
    trace = """\
1000  1700000000.000000 write(5<TCP:[1]>, \"\\x41\\x42\", 2) = 2
"""
    pcap_path = run_converter(tmp_path, trace, args=["--linktype", "ether", "--no-unix-to-tcp"])

    lines = capinfos_lines(pcap_path)
    assert any("Ethernet" in line for line in lines)
