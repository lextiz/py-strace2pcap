"""Synthesize Ethernet/IP/TCP packets for UNIX stream sockets."""

from __future__ import annotations

import ipaddress
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
            # Default to side A when more than two owners appear.
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
    ) -> None:
        self._flows: Dict[Tuple[str, int, int, int], Flow] = {}
        self._flows_by_inode: Dict[int, Flow] = {}
        self._base_src_ip = ipaddress.IPv4Address(base_src_ip)
        self._base_dst_ip = ipaddress.IPv4Address(base_dst_ip)
        self._base_sport = base_sport
        self._dst_port = dst_port
        self._next_index = 0
        self._ip_id = 0

    def handle_event(self, event) -> List[PacketRecord]:
        """Process a parsed strace event and return packets to emit."""

        if not event:
            return []
        if event.get("protocol") != "UNIX-STREAM":
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
            return self._handle_payload(flow, side, event, time_float)
        if syscall in READ_SYSCALLS:
            sender = Flow.opposite(side)
            return self._handle_payload(flow, sender, event, time_float)
        if syscall in STATE_SYSCALLS:
            return self._handle_state(flow, side, syscall, event, time_float)
        return []

    def flush(self) -> Iterable[PacketRecord]:
        """Return packets that should be emitted when processing ends."""

        return []

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

    def _handle_payload(
        self, flow: Flow, sender: str, event, time_float: float
    ) -> List[PacketRecord]:
        result = event.get("result")
        payload: bytes = event.get("payload") or b""
        if not isinstance(result, int) or result <= 0 or not payload:
            return []
        data = payload[:result]
        packets: List[PacketRecord] = []
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, time_float))
        seq, ack = self._seq_ack_for(flow, sender)
        tcp_flags = TCP_FLAG_PSH | TCP_FLAG_ACK
        packets.append(
            self._build_record(
                flow,
                sender,
                seq,
                ack,
                tcp_flags,
                data,
                time_float,
            )
        )
        self._advance_after_payload(flow, sender, len(data))
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
        if not flow.handshake_done:
            # Ensure the connection exists before FIN.
            handshake_ts = time_float
            packets = self._emit_handshake(flow, handshake_ts)
        else:
            packets = []
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
        packets.append(fin_packet)
        peer = Flow.opposite(side)
        ack_time = time_float + 0.00005
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

    def _emit_handshake(self, flow: Flow, first_payload_ts: float) -> List[PacketRecord]:
        if flow.handshake_done:
            return []
        syn_time = max(0.0, first_payload_ts - 0.0003)
        synack_candidate = first_payload_ts - 0.0002
        synack_time = synack_candidate if synack_candidate > syn_time else syn_time + 0.00005
        ack_candidate = first_payload_ts - 0.0001
        ack_time = ack_candidate if ack_candidate > synack_time else synack_time + 0.00005
        if ack_time >= first_payload_ts:
            ack_time = max(synack_time + 0.00001, first_payload_ts - 0.000001)
        packets: List[PacketRecord] = []
        # SYN
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
        # SYN-ACK
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
        # ACK
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
