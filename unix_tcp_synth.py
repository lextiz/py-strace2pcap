"""Synthesize Ethernet/IP/TCP packets for UNIX stream sockets."""

from __future__ import annotations

import ipaddress
import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

WRITE_SYSCALLS = {"write", "sendmsg", "sendto"}
READ_SYSCALLS = {"read", "recvmsg", "recvfrom"}
STATE_SYSCALLS = {"close", "shutdown"}

ETHERTYPE_IPV4 = 0x0800
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10

HANDSHAKE_DELTA = 0.0001
MAX_HTTP2_FRAME_SIZE = (1 << 24) - 1
VALID_STREAM_ZERO_TYPES = {0x4, 0x6, 0x7, 0x8}
TIMESTAMP_EPSILON = 1e-6

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_CLIENT_SETTINGS_FRAME = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
HTTP2_SETTINGS_ACK_FRAME = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
HTTP2_CLIENT_SEED = HTTP2_PREFACE + HTTP2_CLIENT_SETTINGS_FRAME
GRPC_HEADERS_BLOCK = bytes.fromhex(
    "8386449462ba0642ce7a242d8bee2d9dcc42b1a0a99cf27f4186a0e41d139d095f8b1d75d0620d263d4c4d65644082497f864d833505b11f"
)
GRPC_HEADERS_FRAME = b"\x00\x00\x38\x01\x04\x00\x00\x00\x01" + GRPC_HEADERS_BLOCK


@dataclass
class PacketRecord:
    """A packet ready to be written to the PCAP file."""

    ts_sec: int
    ts_usec: int
    data: bytes


@dataclass
class Flow:
    """State tracked for a single UNIX stream inode."""

    inode: Optional[int]
    index: int
    client_ip: str
    server_ip: str
    client_mac: bytes
    server_mac: bytes
    client_port: int
    server_port: int
    isn_client: int
    isn_server: int
    next_seq: Dict[str, int] = field(default_factory=lambda: {"A": 0, "B": 0})
    handshake_done: bool = False
    closed: Dict[str, bool] = field(default_factory=lambda: {"A": False, "B": False})
    owners: Dict[Tuple[int, int, int], str] = field(default_factory=dict)
    buffers: Dict[str, bytearray] = field(default_factory=lambda: {"A": bytearray(), "B": bytearray()})
    buffer_start: Dict[str, Optional[float]] = field(default_factory=lambda: {"A": None, "B": None})
    last_event_ts: Dict[str, Optional[float]] = field(default_factory=lambda: {"A": None, "B": None})
    preface_done: bool = False
    seed_http2_done: bool = False
    seed_grpc_done: bool = False

    def owner_side(self, owner_key: Tuple[int, int, int]) -> str:
        if owner_key in self.owners:
            return self.owners[owner_key]
        assigned = set(self.owners.values())
        side = "A" if "A" not in assigned else "B"
        self.owners[owner_key] = side
        return side

    @staticmethod
    def opposite(side: str) -> str:
        return "B" if side == "A" else "A"


class UnixTCPManager:
    """Emit synthetic TCP flows for UNIX stream sockets."""

    def __init__(
        self,
        *,
        base_src_ip: str = "10.0.0.0",
        base_dst_ip: str = "10.0.1.0",
        base_sport: int = 30000,
        dst_port: int = 50051,
        seed_http2: bool = False,
        seed_grpc: bool = False,
        no_checksum: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._flows_by_inode: Dict[int, Flow] = {}
        self._flows_by_key: Dict[Tuple[str, int, int, int], Flow] = {}
        self._base_src_ip = ipaddress.IPv4Address(base_src_ip)
        self._base_dst_ip = ipaddress.IPv4Address(base_dst_ip)
        self._base_sport = base_sport
        self._dst_port = dst_port
        self._next_index = 0
        self._ip_id = 0
        self._seed_http2 = seed_http2
        self._seed_grpc = seed_grpc
        self._no_checksum = no_checksum
        self._logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    def handle_event(self, event) -> List[PacketRecord]:
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
        side = flow.owner_side(owner_key)

        if syscall in WRITE_SYSCALLS:
            return self._queue_data(flow, side, result, payload, timestamp)
        if syscall in READ_SYSCALLS:
            sender = Flow.opposite(side)
            return self._queue_data(flow, sender, result, payload, timestamp)
        if syscall in STATE_SYSCALLS:
            return self._handle_close(flow, side, timestamp, syscall, result)
        return []

    def flush(self) -> Iterable[PacketRecord]:
        packets: List[PacketRecord] = []
        seen: set[int] = set()
        for flow in list(self._flows_by_inode.values()) + list(self._flows_by_key.values()):
            if id(flow) in seen:
                continue
            seen.add(id(flow))
            packets.extend(self._flush_side(flow, "A", final=True))
            packets.extend(self._flush_side(flow, "B", final=True))
        return packets

    # ------------------------------------------------------------------
    def _flow_for_event(self, event) -> Flow:
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

    def _create_flow(self, inode: Optional[int]) -> Flow:
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
        flow = Flow(
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
        flow.next_seq["A"] = client_isn
        flow.next_seq["B"] = server_isn
        return flow

    def _mac_for(self, index: int, *, client: bool) -> bytes:
        base = 0x020000000000 if client else 0x020000000100
        return (base + index).to_bytes(6, "big")

    # ------------------------------------------------------------------
    def _queue_data(
        self,
        flow: Flow,
        side: str,
        result: Optional[int],
        payload: bytes,
        timestamp: float,
    ) -> List[PacketRecord]:
        if not isinstance(result, int) or result <= 0:
            return []
        if not isinstance(payload, (bytes, bytearray)):
            return []
        data = bytes(payload[:result])
        if not data:
            return []
        buf = flow.buffers[side]
        if not buf:
            flow.buffer_start[side] = timestamp
        buf.extend(data)
        flow.last_event_ts[side] = timestamp
        return self._flush_side(flow, side, final=False)

    def _handle_close(
        self,
        flow: Flow,
        side: str,
        timestamp: float,
        syscall: str,
        result: Optional[int],
    ) -> List[PacketRecord]:
        if syscall == "shutdown" and result not in (0, None):
            return []
        packets = []
        packets.extend(self._flush_side(flow, side, final=True))
        peer = Flow.opposite(side)
        packets.extend(self._flush_side(flow, peer, final=True))
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, timestamp))
        packets.extend(self._maybe_seed(flow, timestamp))
        if not flow.closed[side]:
            seq = flow.next_seq[side]
            ack = flow.next_seq[peer]
            packets.append(
                self._build_record(
                    flow,
                    side,
                    seq,
                    ack,
                    TCP_FLAG_FIN | TCP_FLAG_ACK,
                    b"",
                    timestamp,
                )
            )
            flow.next_seq[side] += 1
            flow.closed[side] = True
        ack_time = max(timestamp + HANDSHAKE_DELTA / 2, timestamp)
        packets.append(
            self._build_record(
                flow,
                peer,
                flow.next_seq[peer],
                flow.next_seq[side],
                TCP_FLAG_ACK,
                b"",
                ack_time,
            )
        )
        return packets

    # ------------------------------------------------------------------
    def _flush_side(self, flow: Flow, side: str, *, final: bool) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        buf = flow.buffers[side]
        if not buf:
            return packets
        start_ts = flow.buffer_start[side] or flow.last_event_ts[side] or 0.0
        outputs: List[Tuple[bytes, bool, Optional[str]]] = []

        while buf:
            if side == "A" and not flow.preface_done and len(buf) >= len(HTTP2_PREFACE) and buf.startswith(HTTP2_PREFACE):
                outputs.append((bytes(buf[: len(HTTP2_PREFACE)]), False, "preface"))
                del buf[: len(HTTP2_PREFACE)]
                flow.preface_done = True
                continue

            if len(buf) < 9:
                break

            header = bytes(buf[:9])
            parsed = _parse_http2_header(header)
            if parsed is None:
                offset = self._find_alignment(buf)
                if offset is None:
                    break
                chunk = bytes(buf[:offset])
                del buf[:offset]
                if chunk:
                    self._logger.warning(
                        "unix flow %s emitted %d opaque bytes while seeking HTTP/2 resync",
                        flow.inode,
                        len(chunk),
                    )
                    outputs.append((chunk, False, "opaque"))
                continue

            length, _, _, _ = parsed
            total = length + 9
            if total > len(buf):
                break

            frame = bytes(buf[:total])
            del buf[:total]
            outputs.append((frame, True, None))

        if final and buf:
            outputs.append((bytes(buf), False, "final"))
            buf.clear()

        if not outputs:
            return packets

        for idx, (payload, is_frame, reason) in enumerate(outputs):
            ts = max(start_ts + idx * TIMESTAMP_EPSILON, 0.0)
            packets.extend(
                self._emit_payload(flow, side, payload, ts, is_frame=is_frame, reason=reason)
            )

        flow.buffer_start[side] = flow.last_event_ts[side] if buf else None
        return packets

    def _find_alignment(self, buf: bytearray) -> Optional[int]:
        for offset in range(1, len(buf)):
            candidate = buf[offset:offset + 9]
            if len(candidate) < 9:
                return None
            if _parse_http2_header(bytes(candidate)) is not None:
                return offset
        return None

    def _emit_payload(
        self,
        flow: Flow,
        side: str,
        payload: bytes,
        ts: float,
        *,
        is_frame: bool,
        reason: Optional[str],
    ) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        packets.extend(self._emit_handshake(flow, ts))
        packets.extend(self._maybe_seed(flow, ts))
        seq = flow.next_seq[side]
        peer = Flow.opposite(side)
        ack = flow.next_seq[peer]
        if not payload:
            return packets
        packets.append(
            self._build_record(
                flow,
                side,
                seq,
                ack,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                payload,
                ts,
            )
        )
        flow.next_seq[side] += len(payload)
        if not is_frame:
            if reason == "preface":
                self._logger.info(
                    "unix flow %s forwarded HTTP/2 client preface (%d bytes)",
                    flow.inode,
                    len(payload),
                )
            else:
                self._logger.warning(
                    "unix flow %s flushed %d non-frame bytes from side %s (%s)",
                    flow.inode,
                    len(payload),
                    side,
                    reason or "opaque",
                )
        return packets

    def _emit_handshake(self, flow: Flow, ts: float) -> List[PacketRecord]:
        if flow.handshake_done:
            return []
        packets: List[PacketRecord] = []
        base = max(ts - 3 * HANDSHAKE_DELTA, 0.0)
        seq_a = flow.next_seq["A"]
        packets.append(
            self._build_record(
                flow,
                "A",
                seq_a,
                0,
                TCP_FLAG_SYN,
                b"",
                base,
            )
        )
        flow.next_seq["A"] += 1
        seq_b = flow.next_seq["B"]
        packets.append(
            self._build_record(
                flow,
                "B",
                seq_b,
                flow.next_seq["A"],
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                b"",
                base + HANDSHAKE_DELTA,
            )
        )
        flow.next_seq["B"] += 1
        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_ACK,
                b"",
                base + 2 * HANDSHAKE_DELTA,
            )
        )
        flow.handshake_done = True
        return packets

    def _maybe_seed(self, flow: Flow, ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        if self._seed_http2 and not flow.preface_done:
            packets.extend(self._emit_http2_seed(flow, ts))
        if self._seed_grpc and not flow.seed_grpc_done:
            packets.extend(self._emit_grpc_seed(flow, ts))
        return packets

    def _emit_http2_seed(self, flow: Flow, ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        client_time = max(ts - 4 * TIMESTAMP_EPSILON, 0.0)
        server_time = client_time + TIMESTAMP_EPSILON
        ack_time = server_time + TIMESTAMP_EPSILON
        server_ack_time = ack_time + TIMESTAMP_EPSILON

        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_CLIENT_SEED,
                client_time,
            )
        )
        flow.next_seq["A"] += len(HTTP2_CLIENT_SEED)
        packets.append(
            self._build_record(
                flow,
                "B",
                flow.next_seq["B"],
                flow.next_seq["A"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_CLIENT_SETTINGS_FRAME,
                server_time,
            )
        )
        flow.next_seq["B"] += len(HTTP2_CLIENT_SETTINGS_FRAME)
        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_SETTINGS_ACK_FRAME,
                ack_time,
            )
        )
        flow.next_seq["A"] += len(HTTP2_SETTINGS_ACK_FRAME)
        packets.append(
            self._build_record(
                flow,
                "B",
                flow.next_seq["B"],
                flow.next_seq["A"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_SETTINGS_ACK_FRAME,
                server_ack_time,
            )
        )
        flow.next_seq["B"] += len(HTTP2_SETTINGS_ACK_FRAME)
        flow.preface_done = True
        flow.seed_http2_done = True
        return packets

    def _emit_grpc_seed(self, flow: Flow, ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        seed_time = max(ts - TIMESTAMP_EPSILON, 0.0)
        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                GRPC_HEADERS_FRAME,
                seed_time,
            )
        )
        flow.next_seq["A"] += len(GRPC_HEADERS_FRAME)
        flow.seed_grpc_done = True
        return packets

    # ------------------------------------------------------------------
    def _build_record(
        self,
        flow: Flow,
        side: str,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
        ts: float,
    ) -> PacketRecord:
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
        ts_sec, ts_usec = self._split_ts(ts)
        return PacketRecord(ts_sec=ts_sec, ts_usec=ts_usec, data=packet)

    def _build_ipv4_header(self, src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
        version_ihl = 0x45
        tos = 0
        total_length = 20 + tcp_len
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        flags_fragment = 0
        ttl = 64
        proto = 6
        checksum = 0
        src = ipaddress.IPv4Address(src_ip).packed
        dst = ipaddress.IPv4Address(dst_ip).packed
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            self._ip_id,
            flags_fragment,
            ttl,
            proto,
            checksum,
            src,
            dst,
        )
        checksum = _checksum(header)
        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            self._ip_id,
            flags_fragment,
            ttl,
            proto,
            checksum,
            src,
            dst,
        )

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
    ) -> Tuple[bytes, int]:
        data_offset = 5 << 12
        window = 65535
        urgent = 0
        checksum = 0
        header = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            data_offset | flags,
            window,
            checksum,
            urgent,
        )
        if not self._no_checksum:
            checksum = _tcp_checksum(src_ip, dst_ip, header, payload)
            header = struct.pack(
                "!HHIIHHHH",
                src_port,
                dst_port,
                seq,
                ack,
                data_offset | flags,
                window,
                checksum,
                urgent,
            )
        return header, len(header) + len(payload)

    def _split_ts(self, ts: float) -> Tuple[int, int]:
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
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) + data[i + 1]
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def _parse_http2_header(header: bytes) -> Optional[Tuple[int, int, int, int]]:
    if len(header) < 9:
        return None
    length = int.from_bytes(header[:3], "big")
    if length > MAX_HTTP2_FRAME_SIZE:
        return None
    frame_type = header[3]
    if frame_type > 0x9:
        return None
    flags = header[4]
    stream_raw = int.from_bytes(header[5:9], "big")
    if stream_raw & 0x80000000:
        return None
    stream_id = stream_raw & 0x7FFFFFFF
    if stream_id == 0 and frame_type not in VALID_STREAM_ZERO_TYPES:
        return None
    return length, frame_type, flags, stream_id


def _tcp_checksum(src_ip: str, dst_ip: str, header: bytes, payload: bytes) -> int:
    pseudo = (
        ipaddress.IPv4Address(src_ip).packed
        + ipaddress.IPv4Address(dst_ip).packed
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    return _checksum(pseudo + header + payload)
