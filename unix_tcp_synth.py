from __future__ import annotations

import ipaddress
import logging
import struct
from dataclasses import dataclass, field
from typing import Optional

WRITE_SYSCALLS = {"write", "sendmsg", "sendto"}
READ_SYSCALLS = {"read", "recvmsg", "recvfrom"}
STATE_SYSCALLS = {"close", "shutdown"}

ETHERTYPE_IPV4 = 0x0800
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10

HANDSHAKE_DELTA = 0.0001
TIMESTAMP_EPSILON = 1e-6
MAX_HTTP2_FRAME_SIZE = (1 << 24) - 1
MAX_TCP_PAYLOAD = 65535 - 20 - 20

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_CLIENT_SETTINGS_FRAME = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
HTTP2_SETTINGS_ACK_FRAME = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
HTTP2_CLIENT_SEED = HTTP2_PREFACE + HTTP2_CLIENT_SETTINGS_FRAME
VALID_STREAM_ZERO_TYPES = {0x4, 0x6, 0x7, 0x8}
GRPC_HEADERS_FRAME = bytes.fromhex(
    "00008101040000000140073a6d6574686f6404504f535440073a736368656d65046874747040053a70"
    "6174681b2f706c616365686f6c6465722e536572766963652f4d6574686f64400a3a617574686f7269"
    "7479096c6f63616c686f7374400c636f6e74656e742d74797065106170706c69636174696f6e2f6770"
    "72634002746508747261696c657273"
)


@dataclass
class PacketRecord:
    ts_sec: int
    ts_usec: int
    data: bytes


@dataclass
class SideState:
    buffer: bytearray = field(default_factory=bytearray)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    in_bytes: int = 0
    out_bytes: int = 0
    closed: bool = False
    accounted: bool = False


class Flow:
    def __init__(
        self,
        *,
        inode,
        index,
        client_ip,
        server_ip,
        client_mac,
        server_mac,
        client_port,
        server_port,
        isn_client,
        isn_server,
    ) -> None:
        self.inode = inode
        self.index = index
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_mac = client_mac
        self.server_mac = server_mac
        self.client_port = client_port
        self.server_port = server_port
        self.next_seq = {"A": isn_client, "B": isn_server}
        self.handshake_done = False
        self.seed_http2_done = False
        self.seed_grpc_done = False
        self.grpc_evidence = False
        self.sides = {"A": SideState(), "B": SideState()}
        self.owners = {}

    @staticmethod
    def peer(side):
        return "B" if side == "A" else "A"

    def side_for(self, owner_key):
        side = self.owners.get(owner_key)
        if side:
            return side
        assigned = set(self.owners.values())
        side = "A" if "A" not in assigned else "B"
        self.owners[owner_key] = side
        return side


class UnixTCPManager:
    """Emit Ethernet/IP/TCP packets for UNIX stream traffic."""

    def __init__(
        self,
        *,
        base_src_ip: str = "10.0.0.0",
        base_dst_ip: str = "10.0.1.0",
        base_sport: int = 30000,
        dst_port: int = 50051,
        seed_http2: bool = False,
        seed_grpc: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._flows_by_inode = {}
        self._flows_by_key = {}
        self._base_src_ip = ipaddress.IPv4Address(base_src_ip)
        self._base_dst_ip = ipaddress.IPv4Address(base_dst_ip)
        self._base_sport = base_sport
        self._dst_port = dst_port
        self._next_index = 0
        self._ip_id = 0
        self._seed_http2 = seed_http2
        self._seed_grpc = seed_grpc
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    def handle_event(self, event):
        if not event or event.get("protocol") != "UNIX-STREAM":
            return []
        syscall = event.get("syscall") or ""
        result = event.get("result")
        payload: bytes = event.get("payload") or b""
        timestamp = float(event.get("time", 0.0))
        owner_key = (
            int(event.get("pid") or 0),
            int(event.get("fd") or 0),
            int(event.get("session") or 0),
        )
        flow = self._flow_for_event(event)
        side = flow.side_for(owner_key)

        if syscall in WRITE_SYSCALLS:
            return self._queue_bytes(flow, side, result, payload, timestamp)
        if syscall in READ_SYSCALLS:
            sender = Flow.peer(side)
            return self._queue_bytes(flow, sender, result, payload, timestamp)
        if syscall in STATE_SYSCALLS:
            return self._handle_close(flow, side, timestamp, syscall, result)
        return []

    def flush(self):
        seen: set[int] = set()
        packets = []
        for flow in list(self._flows_by_inode.values()) + list(self._flows_by_key.values()):
            if id(flow) in seen:
                continue
            seen.add(id(flow))
            packets.extend(self._drain_side(flow, "A", final=True))
            packets.extend(self._drain_side(flow, "B", final=True))
        return packets

    # ------------------------------------------------------------------
    def _flow_for_event(self, event):
        inode = event.get("inode")
        if isinstance(inode, int):
            flow = self._flows_by_inode.get(inode)
            if flow is None:
                flow = self._create_flow(inode)
                self._flows_by_inode[inode] = flow
            return flow

        key = (
            event.get("protocol", ""),
            int(event.get("pid") or 0),
            int(event.get("fd") or 0),
            int(event.get("session") or 0),
        )
        flow = self._flows_by_key.get(key)
        if flow is None:
            flow = self._create_flow(None)
            self._flows_by_key[key] = flow
        return flow

    def _create_flow(self, inode):
        index = self._next_index
        self._next_index += 1
        client_ip = str(self._base_src_ip + index + 1)
        server_ip = str(self._base_dst_ip + index + 1)
        client_mac = self._mac_for(index, client=True)
        server_mac = self._mac_for(index, client=False)
        inode_seed = inode if inode is not None else 100000 + index
        client_port = self._base_sport + (inode_seed % 10000)
        client_isn = 0x10000000 + inode_seed
        server_isn = 0x20000000 + inode_seed
        return Flow(
            inode=inode,
            index=index,
            client_ip=client_ip,
            server_ip=server_ip,
            client_mac=client_mac,
            server_mac=server_mac,
            client_port=client_port,
            server_port=self._dst_port,
            isn_client=client_isn,
            isn_server=server_isn,
        )

    def _mac_for(self, index, *, client: bool) -> bytes:
        base = 0x020000000000 if client else 0x020000000100
        return (base + index).to_bytes(6, "big")

    # ------------------------------------------------------------------
    def _queue_bytes(self, flow, side, result, payload, timestamp):
        if not isinstance(result, int) or result <= 0:
            return []
        emit_len = min(result, len(payload))
        if emit_len <= 0:
            return []
        chunk = bytes(payload[:emit_len])
        state = flow.sides[side]
        if not state.buffer:
            state.first_ts = timestamp
        state.buffer.extend(chunk)
        state.last_ts = timestamp
        state.in_bytes += len(chunk)
        return self._drain_side(flow, side, final=False)

    def _handle_close(self, flow, side, timestamp, syscall, result):
        if syscall == "shutdown" and result not in (0, None):
            return []
        packets = []
        packets.extend(self._drain_side(flow, side, final=True))
        peer = Flow.peer(side)
        packets.extend(self._drain_side(flow, peer, final=True))
        packets.extend(self._ensure_warmup(flow, timestamp))
        state = flow.sides[side]
        if not state.closed:
            seq = flow.next_seq[side]
            ack = flow.next_seq[peer]
            packets.append(self._build_record(flow, side, seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK, b"", timestamp))
            flow.next_seq[side] += 1
            state.closed = True
        ack_time = max(timestamp + HANDSHAKE_DELTA / 2, timestamp)
        packets.append(self._build_record(flow, peer, flow.next_seq[peer], flow.next_seq[side], TCP_FLAG_ACK, b"", ack_time))
        return packets

    # ------------------------------------------------------------------
    def _drain_side(self, flow, side, *, final):
        state = flow.sides[side]
        buf = state.buffer
        if not buf:
            if final:
                self._log_accounting(flow, side)
            return []

        outputs = []
        while buf:
            if len(buf) < 9:
                break

            header = bytes(buf[:9])
            parsed = _parse_http2_header(header)
            if parsed is None:
                offset = _find_frame_alignment(buf)
                if offset is None:
                    break
                if offset:
                    chunk = bytes(buf[:offset])
                    del buf[:offset]
                    outputs.append(("opaque", chunk, None))
                continue

            length, frame_type, flags, stream_id = parsed
            total = length + 9
            if total > len(buf):
                break
            frame = bytes(buf[:total])
            del buf[:total]
            outputs.append(("frame", frame, parsed))
            if frame_type in (0, 1, 9):
                self._inspect_frame_for_grpc(flow, frame_type, flags, frame[9:], stream_id)

        if final and buf:
            outputs.append(("final", bytes(buf), None))
            buf.clear()

        if not outputs:
            if final:
                self._log_accounting(flow, side)
            return []

        start_ts = state.first_ts if state.first_ts is not None else (state.last_ts or 0.0)
        packets = []
        for idx, (reason, payload, meta) in enumerate(outputs):
            ts = max(start_ts + idx * TIMESTAMP_EPSILON, 0.0)
            packets.extend(self._emit_payload(flow, side, payload, ts, is_frame=(reason == "frame"), reason=reason))

        if buf:
            state.first_ts = start_ts + len(outputs) * TIMESTAMP_EPSILON
        else:
            state.first_ts = None

        if final:
            self._log_accounting(flow, side)
        return packets

    def _emit_payload(self, flow, side, payload, ts, *, is_frame, reason):
        packets = []
        packets.extend(self._ensure_warmup(flow, ts))
        if not payload:
            return packets

        state = flow.sides[side]
        peer = Flow.peer(side)
        seq_start = flow.next_seq[side]
        ack = flow.next_seq[peer]

        for idx in range(0, len(payload), MAX_TCP_PAYLOAD):
            chunk = payload[idx : idx + MAX_TCP_PAYLOAD]
            chunk_ts = ts + idx * TIMESTAMP_EPSILON
            packets.append(self._build_record(flow, side, seq_start + idx, ack, TCP_FLAG_PSH | TCP_FLAG_ACK, chunk, chunk_ts))

        flow.next_seq[side] += len(payload)
        state.out_bytes += len(payload)

        if reason in {"opaque", "final"}:
            self._logger.warning(
                "unix flow %s flushed %d %s bytes from side %s",
                flow.inode,
                len(payload),
                "opaque" if reason == "opaque" else "trailing",
                side,
            )
        return packets

    def _ensure_warmup(self, flow, ts):
        packets = []
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, ts))
        if self._seed_http2 and not flow.seed_http2_done:
            packets.extend(self._emit_http2_seed(flow, ts))
        if self._seed_grpc and flow.grpc_evidence and not flow.seed_grpc_done:
            packets.extend(self._emit_grpc_seed(flow, ts))
        return packets

    def _emit_handshake(self, flow, ts):
        if flow.handshake_done:
            return []
        base = max(ts - 3 * HANDSHAKE_DELTA, 0.0)
        seq_a = flow.next_seq["A"]
        seq_b = flow.next_seq["B"]
        steps = [
            ("A", seq_a, 0, TCP_FLAG_SYN, base),
            ("B", seq_b, seq_a + 1, TCP_FLAG_SYN | TCP_FLAG_ACK, base + HANDSHAKE_DELTA),
            ("A", seq_a + 1, seq_b + 1, TCP_FLAG_ACK, base + 2 * HANDSHAKE_DELTA),
        ]
        packets = [self._build_record(flow, side, seq, ack, flags, b"", ts) for side, seq, ack, flags, ts in steps]
        flow.next_seq["A"] = seq_a + 1
        flow.next_seq["B"] = seq_b + 1
        flow.handshake_done = True
        return packets

    def _emit_http2_seed(self, flow, ts):
        base = max(ts - 3 * TIMESTAMP_EPSILON, 0.0)
        sequence = [
            ("A", HTTP2_CLIENT_SEED, base),
            ("B", HTTP2_CLIENT_SETTINGS_FRAME, base + TIMESTAMP_EPSILON),
            ("A", HTTP2_SETTINGS_ACK_FRAME, base + 2 * TIMESTAMP_EPSILON),
            ("B", HTTP2_SETTINGS_ACK_FRAME, base + 3 * TIMESTAMP_EPSILON),
        ]
        packets = []
        for side, payload, send_ts in sequence:
            packets.append(
                self._build_record(
                    flow,
                    side,
                    flow.next_seq[side],
                    flow.next_seq[Flow.peer(side)],
                    TCP_FLAG_PSH | TCP_FLAG_ACK,
                    payload,
                    send_ts,
                )
            )
            flow.next_seq[side] += len(payload)
        flow.seed_http2_done = True
        return packets

    def _emit_grpc_seed(self, flow, ts):
        packets = [
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                GRPC_HEADERS_FRAME,
                max(ts - TIMESTAMP_EPSILON, 0.0),
            )
        ]
        flow.next_seq["A"] += len(GRPC_HEADERS_FRAME)
        flow.seed_grpc_done = True
        return packets

    def _inspect_frame_for_grpc(self, flow, frame_type, flags, payload, stream_id):
        if self._seed_grpc and not flow.seed_grpc_done:
            if frame_type == 0 and len(payload) >= 5:
                compressed = payload[0]
                msg_len = int.from_bytes(payload[1:5], "big")
                if compressed in (0, 1) and msg_len <= len(payload) - 5:
                    flow.grpc_evidence = True
            elif frame_type in (1, 9):
                markers = (b"application/grpc", b"grpc-status", b"content-type", b"/Service/")
                if any(marker in payload for marker in markers):
                    flow.grpc_evidence = True

    def _log_accounting(self, flow, side):
        state = flow.sides[side]
        if state.accounted:
            return
        delta = state.in_bytes - state.out_bytes
        level = logging.INFO if delta == 0 else logging.WARNING
        self._logger.log(
            level,
            "unix flow %s side %s delivered %d/%d bytes (delta=%d)",
            flow.inode,
            side,
            state.out_bytes,
            state.in_bytes,
            delta,
        )
        state.accounted = True

    # ------------------------------------------------------------------
    def _build_record(self, flow, side, seq, ack, flags, payload, ts):
        if side == "A":
            src_mac, dst_mac = flow.client_mac, flow.server_mac
            src_ip, dst_ip = flow.client_ip, flow.server_ip
            src_port, dst_port = flow.client_port, flow.server_port
        else:
            src_mac, dst_mac = flow.server_mac, flow.client_mac
            src_ip, dst_ip = flow.server_ip, flow.client_ip
            src_port, dst_port = flow.server_port, flow.client_port

        ethernet = src_mac + dst_mac + struct.pack("!H", ETHERTYPE_IPV4)
        tcp_header, tcp_len = self._build_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
        ip_header = self._build_ipv4_header(src_ip, dst_ip, tcp_len)
        packet = ethernet + ip_header + tcp_header + payload
        ts_sec, ts_usec = _split_ts(ts)
        return PacketRecord(ts_sec=ts_sec, ts_usec=ts_usec, data=packet)

    def _build_ipv4_header(self, src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
        version_ihl = 0x45
        total_length = 20 + tcp_len
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            0,
            total_length,
            self._ip_id,
            0,
            64,
            6,
            0,
            ipaddress.IPv4Address(src_ip).packed,
            ipaddress.IPv4Address(dst_ip).packed,
        )
        checksum = _checksum(header)
        return header[:10] + struct.pack("!H", checksum) + header[12:]

    def _build_tcp_header(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
    ):
        data_offset = 5 << 12
        header = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset | flags,
            65535,
            0,
            0,
        )
        checksum = _tcp_checksum(src_ip, dst_ip, header, payload)
        header = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset | flags,
            65535,
            checksum,
            0,
        )
        return header, len(header) + len(payload)


def _split_ts(ts: float):
    if ts < 0:
        ts = 0.0
    ts_sec = int(ts)
    ts_usec = int(round((ts - ts_sec) * 1_000_000))
    if ts_usec >= 1_000_000:
        ts_sec += 1
        ts_usec -= 1_000_000
    return ts_sec, ts_usec


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    acc = 0
    for idx in range(0, len(data), 2):
        acc += (data[idx] << 8) + data[idx + 1]
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def _tcp_checksum(src_ip: str, dst_ip: str, header: bytes, payload: bytes) -> int:
    pseudo = (
        ipaddress.IPv4Address(src_ip).packed
        + ipaddress.IPv4Address(dst_ip).packed
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    return _checksum(pseudo + header + payload)


def _parse_http2_header(header: bytes):
    if len(header) < 9:
        return None
    length = int.from_bytes(header[:3], "big")
    if length > MAX_HTTP2_FRAME_SIZE:
        return None
    frame_type = header[3]
    if frame_type > 0x9:
        return None
    flags = header[4]
    stream_id = int.from_bytes(header[5:9], "big")
    if stream_id & 0x80000000:
        return None
    stream_id &= 0x7FFFFFFF
    if stream_id == 0 and frame_type not in VALID_STREAM_ZERO_TYPES:
        return None
    return length, frame_type, flags, stream_id


def _find_frame_alignment(buf: bytearray) -> Optional[int]:
    for offset in range(1, len(buf)):
        if len(buf) - offset < 9:
            return None
        if _parse_http2_header(bytes(buf[offset : offset + 9])) is not None:
            return offset
    return None
