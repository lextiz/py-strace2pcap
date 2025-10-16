"""Synthesize Ethernet/IP/TCP packets for UNIX stream sockets."""

from __future__ import annotations

import ipaddress
import logging
import math
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple


WRITE_SYSCALLS = {"write", "sendmsg", "sendto"}
READ_SYSCALLS = {"read", "recvmsg", "recvfrom"}
CLOSE_SYSCALLS = {"close"}
STATE_SYSCALLS = CLOSE_SYSCALLS | {"shutdown"}

ETHERTYPE_IPV4 = 0x0800
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10

COALESCE_WINDOW = 0.0002

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_CLIENT_SETTINGS_FRAME = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
HTTP2_SETTINGS_ACK_FRAME = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
HTTP2_CLIENT_SEED = HTTP2_PREFACE + HTTP2_CLIENT_SETTINGS_FRAME
GRPC_HEADERS_BLOCK = bytes.fromhex(
    "83449462ba0642ce7a242d8bee2d9dcc42b1a0a99cf27f5f8b1d75d0620d263d4c4d65644082497f864d833505b11f"
)
GRPC_HEADERS_FRAME = b"\x00\x00\x2f\x01\x04\x00\x00\x00\x01" + GRPC_HEADERS_BLOCK


@dataclass
class PacketRecord:
    """A packet ready to be written to the PCAP file."""

    ts_sec: int
    ts_usec: int
    data: bytes


def _empty_bytearray_dict() -> Dict[str, bytearray]:
    return {"A": bytearray(), "B": bytearray()}


def _empty_float_dict() -> Dict[str, Optional[float]]:
    return {"A": None, "B": None}


@dataclass
class Flow:
    """State tracked for a single UNIX stream inode."""

    inode: Optional[int]
    index: int
    src_ip: str
    dst_ip: str
    src_mac: bytes
    dst_mac: bytes
    src_port: int
    dst_port: int
    isn_a: int
    isn_b: int
    next_seq_a: int
    next_seq_b: int
    ack_from_a: int
    ack_from_b: int
    handshake_done: bool = False
    owners: Dict[Tuple[int, int, int], str] = field(default_factory=dict)
    fin_sent: set = field(default_factory=set)
    pending_data: Dict[str, bytearray] = field(default_factory=_empty_bytearray_dict)
    pending_start: Dict[str, Optional[float]] = field(default_factory=_empty_float_dict)
    last_event_ts: Dict[str, Optional[float]] = field(default_factory=_empty_float_dict)
    seed_http2_emitted: bool = False
    seed_grpc_emitted: bool = False

    def owner_side(self, owner_key: Tuple[int, int, int]) -> str:
        """Return the flow side ("A" or "B") for a pid/fd/session tuple."""

        if owner_key in self.owners:
            return self.owners[owner_key]
        assigned = set(self.owners.values())
        if "A" not in assigned:
            side = "A"
        elif "B" not in assigned:
            side = "B"
        else:
            side = "A"
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
        coalesce_window: float = COALESCE_WINDOW,
        seed_http2: bool = False,
        seed_grpc: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._flows: Dict[Tuple[str, int, int, int], Flow] = {}
        self._flows_by_inode: Dict[int, Flow] = {}
        self._base_src_ip = ipaddress.IPv4Address(base_src_ip)
        self._base_dst_ip = ipaddress.IPv4Address(base_dst_ip)
        self._base_sport = base_sport
        self._dst_port = dst_port
        self._next_index = 0
        self._ip_id = 0
        self._coalesce_window = coalesce_window
        self._seed_http2 = seed_http2
        self._seed_grpc = seed_grpc
        self._logger = logger or logging.getLogger(__name__)

    def handle_event(self, event) -> List[PacketRecord]:
        """Process a parsed strace event and return packets to emit."""

        if not event or event.get("protocol") != "UNIX-STREAM":
            return []
        syscall = event.get("syscall") or ""
        time_float = float(event.get("time", 0.0))
        owner_key = (
            int(event.get("pid") or 0),
            int(event.get("fd") or 0),
            int(event.get("session") or 0),
        )
        flow = self._flow_for_event(event)
        side = flow.owner_side(owner_key)

        if syscall in WRITE_SYSCALLS:
            return self._queue_payload(flow, side, event, time_float)
        if syscall in READ_SYSCALLS:
            sender = Flow.opposite(side)
            return self._queue_payload(flow, sender, event, time_float)
        if syscall in STATE_SYSCALLS:
            return self._handle_state(flow, side, syscall, event, time_float)
        return []

    def flush(self) -> Iterable[PacketRecord]:
        """Return packets that should be emitted when processing ends."""

        packets: List[PacketRecord] = []
        seen: set[int] = set()
        for flow in list(self._flows_by_inode.values()) + list(self._flows.values()):
            if id(flow) in seen:
                continue
            seen.add(id(flow))
            packets.extend(self._flush_all(flow, flow.pending_start["A"] or flow.pending_start["B"] or 0.0))
        return packets

    # Internal helpers -------------------------------------------------

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
        flow = self._flows.get(key)
        if flow is None:
            flow = self._create_flow(None)
            self._flows[key] = flow
        return flow

    def _create_flow(self, inode: Optional[int]) -> Flow:
        index = self._next_index
        self._next_index += 1
        src_ip = str(self._base_src_ip + index + 1)
        dst_ip = str(self._base_dst_ip + index + 1)
        src_mac = self._mac_for(index, client=True)
        dst_mac = self._mac_for(index, client=False)
        inode_value = inode if inode is not None else (100000 + index)
        src_port = self._base_sport + (inode_value % 10000)
        flow = Flow(
            inode=inode,
            index=index,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_port=src_port,
            dst_port=self._dst_port,
            isn_a=0x10000000 + inode_value,
            isn_b=0x20000000 + inode_value,
            next_seq_a=0x10000000 + inode_value,
            next_seq_b=0x20000000 + inode_value,
            ack_from_a=0x20000000 + inode_value,
            ack_from_b=0x10000000 + inode_value,
        )
        return flow

    def _mac_for(self, index: int, *, client: bool) -> bytes:
        base = 0x020000000000 if client else 0x020000000100
        mac_int = base + index
        return mac_int.to_bytes(6, "big")

    def _queue_payload(self, flow: Flow, sender: str, event, time_float: float) -> List[PacketRecord]:
        result = event.get("result")
        payload: bytes = event.get("payload") or b""
        if not isinstance(result, int) or result <= 0 or not isinstance(payload, (bytes, bytearray)):
            return []
        data = bytes(payload[:result])
        if not data:
            return []
        packets: List[PacketRecord] = []
        packets.extend(self._flush_buffer(flow, Flow.opposite(sender), time_float))
        packets.extend(self._flush_if_timeout(flow, sender, time_float))
        buf = flow.pending_data[sender]
        if not buf:
            flow.pending_start[sender] = time_float
        buf.extend(data)
        flow.last_event_ts[sender] = time_float
        return packets

    def _handle_state(
        self,
        flow: Flow,
        side: str,
        syscall: str,
        event,
        time_float: float,
    ) -> List[PacketRecord]:
        if syscall == "shutdown" and event.get("result", 0) != 0:
            return []
        packets = self._flush_all(flow, time_float)
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, time_float))
        if side in flow.fin_sent:
            return packets
        seq, ack = self._seq_ack_for(flow, side)
        fin_packet = self._build_record(
            flow,
            side,
            seq,
            ack,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            b"",
            time_float,
        )
        self._advance_after_fin(flow, side)
        self._validate_flow(flow, "fin")
        packets.append(fin_packet)
        peer = Flow.opposite(side)
        ack_time = max(time_float + 0.00005, time_float)
        peer_seq, peer_ack = self._seq_ack_for(flow, peer)
        ack_packet = self._build_record(
            flow,
            peer,
            peer_seq,
            peer_ack,
            TCP_FLAG_ACK,
            b"",
            ack_time,
        )
        packets.append(ack_packet)
        flow.fin_sent.add(side)
        return packets

    def _flush_all(self, flow: Flow, reference_ts: float) -> List[PacketRecord]:
        order: List[Tuple[float, str]] = []
        for side in ("A", "B"):
            if flow.pending_data[side]:
                start_ts = flow.pending_start[side]
                order.append((start_ts if start_ts is not None else reference_ts, side))
        order.sort(key=lambda item: item[0])
        packets: List[PacketRecord] = []
        for _, side in order:
            packets.extend(self._flush_buffer(flow, side, reference_ts))
        return packets

    def _flush_if_timeout(self, flow: Flow, side: str, ts: float) -> List[PacketRecord]:
        last_ts = flow.last_event_ts[side]
        if not flow.pending_data[side] or last_ts is None:
            return []
        if ts - last_ts > self._coalesce_window:
            return self._flush_buffer(flow, side, ts)
        return []

    def _flush_buffer(self, flow: Flow, side: str, reference_ts: float) -> List[PacketRecord]:
        buf = flow.pending_data[side]
        if not buf:
            return []
        flush_ts = flow.pending_start[side]
        if flush_ts is None:
            flush_ts = reference_ts
        data = bytes(buf)
        buf.clear()
        flow.pending_start[side] = None
        flow.last_event_ts[side] = None
        return self._emit_payload(flow, side, data, flush_ts)

    def _emit_payload(self, flow: Flow, side: str, data: bytes, ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, ts))
        packets.extend(self._maybe_seed(flow, ts))
        seq, ack = self._seq_ack_for(flow, side)
        tcp_flags = TCP_FLAG_PSH | TCP_FLAG_ACK
        packets.append(
            self._build_record(
                flow,
                side,
                seq,
                ack,
                tcp_flags,
                data,
                ts,
            )
        )
        self._advance_after_payload(flow, side, len(data))
        self._validate_flow(flow, f"payload-{side}")
        return packets

    def _maybe_seed(self, flow: Flow, first_payload_ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        if self._seed_http2 and not flow.seed_http2_emitted:
            packets.extend(self._seed_http2_frames(flow, first_payload_ts))
        if self._seed_grpc and not flow.seed_grpc_emitted:
            packets.extend(self._seed_grpc_frame(flow, first_payload_ts))
        return packets

    def _seed_http2_frames(self, flow: Flow, first_payload_ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        client_time = max(0.0, first_payload_ts - 0.00009)
        server_time = max(client_time + 0.00002, first_payload_ts - 0.00006)
        seq_a, ack_a = self._seq_ack_for(flow, "A")
        packets.append(
            self._build_record(
                flow,
                "A",
                seq_a,
                ack_a,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_CLIENT_SEED,
                client_time,
            )
        )
        self._advance_after_payload(flow, "A", len(HTTP2_CLIENT_SEED))
        self._validate_flow(flow, "seed-http2-client")
        seq_b, ack_b = self._seq_ack_for(flow, "B")
        packets.append(
            self._build_record(
                flow,
                "B",
                seq_b,
                ack_b,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                HTTP2_SETTINGS_ACK_FRAME,
                server_time,
            )
        )
        self._advance_after_payload(flow, "B", len(HTTP2_SETTINGS_ACK_FRAME))
        self._validate_flow(flow, "seed-http2-server")
        flow.seed_http2_emitted = True
        return packets

    def _seed_grpc_frame(self, flow: Flow, first_payload_ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        headers_time = max(0.0, first_payload_ts - 0.00003)
        seq_a, ack_a = self._seq_ack_for(flow, "A")
        packets.append(
            self._build_record(
                flow,
                "A",
                seq_a,
                ack_a,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                GRPC_HEADERS_FRAME,
                headers_time,
            )
        )
        self._advance_after_payload(flow, "A", len(GRPC_HEADERS_FRAME))
        self._validate_flow(flow, "seed-grpc")
        flow.seed_grpc_emitted = True
        return packets

    def _emit_handshake(self, flow: Flow, first_payload_ts: float) -> List[PacketRecord]:
        if flow.handshake_done:
            return []
        syn_time = max(0.0, first_payload_ts - 0.0003)
        synack_time = max(syn_time + 0.00005, first_payload_ts - 0.0002)
        ack_time = max(synack_time + 0.00005, first_payload_ts - 0.0001)
        packets: List[PacketRecord] = []
        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq_a,
                0,
                TCP_FLAG_SYN,
                b"",
                syn_time,
            )
        )
        flow.next_seq_a += 1
        flow.ack_from_b = flow.next_seq_a
        packets.append(
            self._build_record(
                flow,
                "B",
                flow.next_seq_b,
                flow.next_seq_a,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                b"",
                synack_time,
            )
        )
        flow.next_seq_b += 1
        flow.ack_from_a = flow.next_seq_b
        packets.append(
            self._build_record(
                flow,
                "A",
                flow.next_seq_a,
                flow.next_seq_b,
                TCP_FLAG_ACK,
                b"",
                ack_time,
            )
        )
        flow.handshake_done = True
        self._validate_flow(flow, "handshake")
        return packets

    def _seq_ack_for(self, flow: Flow, side: str) -> Tuple[int, int]:
        if side == "A":
            return flow.next_seq_a, flow.ack_from_a
        return flow.next_seq_b, flow.ack_from_b

    def _advance_after_payload(self, flow: Flow, side: str, length: int) -> None:
        if side == "A":
            flow.next_seq_a += length
            flow.ack_from_b = flow.next_seq_a
        else:
            flow.next_seq_b += length
            flow.ack_from_a = flow.next_seq_b

    def _advance_after_fin(self, flow: Flow, side: str) -> None:
        if side == "A":
            flow.next_seq_a += 1
            flow.ack_from_b = flow.next_seq_a
        else:
            flow.next_seq_b += 1
            flow.ack_from_a = flow.next_seq_b

    def _build_record(
        self,
        flow: Flow,
        side: str,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
        time_float: float,
    ) -> PacketRecord:
        packet = self._build_packet(flow, side, seq, ack, flags, payload)
        return PacketRecord(*self._ts_parts(time_float), packet)

    def _build_packet(
        self,
        flow: Flow,
        side: str,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
    ) -> bytes:
        src_ip = flow.src_ip if side == "A" else flow.dst_ip
        dst_ip = flow.dst_ip if side == "A" else flow.src_ip
        src_mac = flow.src_mac if side == "A" else flow.dst_mac
        dst_mac = flow.dst_mac if side == "A" else flow.src_mac
        src_port = flow.src_port if side == "A" else flow.dst_port
        dst_port = flow.dst_port if side == "A" else flow.src_port

        ip_header, tcp_header = self._build_headers(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
        )
        eth_header = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPV4)
        return eth_header + ip_header + tcp_header + payload

    def _build_headers(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
    ) -> Tuple[bytes, bytes]:
        tcp_header = self._build_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
        ip_header = self._build_ip_header(src_ip, dst_ip, len(tcp_header) + len(payload))
        return ip_header, tcp_header

    def _build_ip_header(self, src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
        version_ihl = 0x45
        tos = 0
        total_length = 20 + tcp_len
        self._ip_id = (self._ip_id + 1) % 65536
        flags_fragment = 0
        ttl = 64
        protocol = 6
        checksum = 0
        src_bytes = ipaddress.IPv4Address(src_ip).packed
        dst_bytes = ipaddress.IPv4Address(dst_ip).packed
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            self._ip_id,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_bytes,
            dst_bytes,
        )
        checksum = self._checksum(header)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            self._ip_id,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_bytes,
            dst_bytes,
        )
        return header

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
    ) -> bytes:
        data_offset = 5
        window = 65535
        checksum = 0
        urgent = 0
        offset_flags = (data_offset << 12) | flags
        header = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            offset_flags,
            window,
            checksum,
            urgent,
        )
        checksum = self._tcp_checksum(src_ip, dst_ip, header, payload)
        header = struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            offset_flags,
            window,
            checksum,
            urgent,
        )
        return header

    def _tcp_checksum(self, src_ip: str, dst_ip: str, header: bytes, payload: bytes) -> int:
        pseudo_header = (
            ipaddress.IPv4Address(src_ip).packed
            + ipaddress.IPv4Address(dst_ip).packed
            + struct.pack("!BBH", 0, 6, len(header) + len(payload))
        )
        checksum_input = pseudo_header + header + payload
        if len(checksum_input) % 2:
            checksum_input += b"\x00"
        return self._checksum(checksum_input)

    def _checksum(self, data: bytes) -> int:
        acc = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            acc += word
            acc = (acc & 0xFFFF) + (acc >> 16)
        return (~acc) & 0xFFFF

    def _ts_parts(self, ts: float) -> Tuple[int, int]:
        frac, integer = math.modf(ts)
        sec = int(integer)
        usec = int(round(frac * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        if sec < 0:
            sec = 0
        if usec < 0:
            usec = 0
        return sec, usec

    def _validate_flow(self, flow: Flow, context: str) -> None:
        if not flow.handshake_done:
            return
        expected_ack_from_a = flow.next_seq_b
        expected_ack_from_b = flow.next_seq_a
        if flow.ack_from_a != expected_ack_from_a or flow.ack_from_b != expected_ack_from_b:
            self._logger.warning(
                "TCP continuity warning for inode %s (%s): ack_from_a=%s expected=%s ack_from_b=%s expected=%s",
                flow.inode,
                context,
                flow.ack_from_a,
                expected_ack_from_a,
                flow.ack_from_b,
                expected_ack_from_b,
            )
