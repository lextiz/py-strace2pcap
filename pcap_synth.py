"""Utilities for synthesizing TCP/UDP packets for AF_UNIX sockets."""

from __future__ import annotations

"""Utilities for synthesizing TCP/UDP packets for AF_UNIX sockets."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import ipaddress

from scapy.all import IP, TCP, UDP, Raw, Ether


@dataclass
class PacketSpec:
    """Description of a packet to be rendered with scapy."""

    layer4: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: str = ""
    timestamp: float = 0.0


@dataclass
class UnixSynthConfig:
    """Configuration for AF_UNIX synthetic flow generation."""

    enable: bool = True
    base_ip_a: str = "10.0.0.1"
    base_ip_b: str = "10.0.1.1"
    base_sport: int = 30000
    base_dport: int = 40000
    handshake_deltas: Tuple[float, float, float] = (-0.0003, -0.0002, -0.0001)
    ack_delta: float = 0.00005
    linktype: str = "raw"

    def __post_init__(self) -> None:
        self._base_ip_a = ipaddress.IPv4Address(self.base_ip_a)
        self._base_ip_b = ipaddress.IPv4Address(self.base_ip_b)

    def ip_for_a(self, offset: int) -> str:
        return str(self._base_ip_a + offset)

    def ip_for_b(self, offset: int) -> str:
        return str(self._base_ip_b + offset)

    def sport_for_inode(self, inode: int) -> int:
        return self.base_sport + (inode % 10000)

    def dport_for_inode(self, inode: int) -> int:
        return self.base_dport + (inode % 10000)


EndpointKey = Tuple[int, int, int]


@dataclass
class UnixStreamFlow:
    inode: int
    index: int
    config: UnixSynthConfig
    type_hint: Optional[str] = None
    path: Optional[str] = None
    endpoints: Dict[EndpointKey, str] = field(default_factory=dict)
    role_hints: Dict[EndpointKey, str] = field(default_factory=dict)
    handshake_done: bool = False
    isn_a: int = field(init=False)
    isn_b: int = field(init=False)
    next_seq: Dict[str, int] = field(init=False)
    peer_ack: Dict[str, int] = field(init=False)
    closed_sides: set = field(default_factory=set)

    def __post_init__(self) -> None:
        self.isn_a = (0x10000000 + self.inode) & 0xFFFFFFFF
        self.isn_b = (0x20000000 + self.inode) & 0xFFFFFFFF
        self.next_seq = {
            "A": self.isn_a,
            "B": self.isn_b,
        }
        self.peer_ack = {
            "A": 0,
            "B": 0,
        }

    def ip_for(self, side: str) -> str:
        if side == "A":
            return self.config.ip_for_a(self.index)
        return self.config.ip_for_b(self.index)

    def port_for(self, side: str) -> int:
        if side == "A":
            return self.config.sport_for_inode(self.inode)
        return self.config.dport_for_inode(self.inode)

    def other(self, side: str) -> str:
        return "B" if side == "A" else "A"

    def preferred_side(self, endpoint: EndpointKey) -> Optional[str]:
        hint = self.role_hints.get(endpoint)
        if hint == "client":
            return "A"
        if hint == "server":
            return "B"
        return None

    def assign_side(self, endpoint: EndpointKey, prefer: Optional[str] = None) -> str:
        if endpoint in self.endpoints:
            return self.endpoints[endpoint]
        preferred = prefer or self.preferred_side(endpoint)
        if not self.endpoints:
            side = preferred or "A"
        elif len(self.endpoints) == 1:
            existing = next(iter(self.endpoints.values()))
            if preferred and preferred != existing:
                side = preferred
            else:
                side = self.other(existing)
        else:
            side = preferred or "A"
        self.endpoints[endpoint] = side
        return side

    def set_role_hint(self, endpoint: EndpointKey, hint: str) -> None:
        self.role_hints[endpoint] = hint

    def set_path(self, path: Optional[str]) -> None:
        if path:
            self.path = path

    def ensure_handshake(self, timestamp: float, initiator: str) -> List[PacketSpec]:
        if self.handshake_done:
            return []
        responder = self.other(initiator)
        packets: List[PacketSpec] = []
        deltas = self.config.handshake_deltas
        syn_time = timestamp + deltas[0]
        synack_time = timestamp + deltas[1]
        ack_time = timestamp + deltas[2]
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(initiator),
                dst_ip=self.ip_for(responder),
                src_port=self.port_for(initiator),
                dst_port=self.port_for(responder),
                payload=b"",
                seq=self.isn_a if initiator == "A" else self.isn_b,
                ack=0,
                flags="S",
                timestamp=syn_time,
            )
        )
        self.next_seq[initiator] = (self.next_seq[initiator] + 1) & 0xFFFFFFFF
        synack_seq = self.isn_b if initiator == "A" else self.isn_a
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(responder),
                dst_ip=self.ip_for(initiator),
                src_port=self.port_for(responder),
                dst_port=self.port_for(initiator),
                payload=b"",
                seq=synack_seq,
                ack=self.next_seq[initiator],
                flags="SA",
                timestamp=synack_time,
            )
        )
        self.next_seq[responder] = (self.next_seq[responder] + 1) & 0xFFFFFFFF
        self.peer_ack[initiator] = self.next_seq[responder]
        self.peer_ack[responder] = self.next_seq[initiator]
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(initiator),
                dst_ip=self.ip_for(responder),
                src_port=self.port_for(initiator),
                dst_port=self.port_for(responder),
                payload=b"",
                seq=self.next_seq[initiator],
                ack=self.next_seq[responder],
                flags="A",
                timestamp=ack_time,
            )
        )
        self.handshake_done = True
        return packets

    def data_packet(
        self,
        timestamp: float,
        sender: str,
        payload: bytes,
        push_flag: bool = True,
    ) -> List[PacketSpec]:
        packets: List[PacketSpec] = []
        receiver = self.other(sender)
        seq = self.next_seq[sender]
        ack = self.peer_ack.get(sender, self.next_seq[receiver])
        flags = "PA" if push_flag else "A"
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(sender),
                dst_ip=self.ip_for(receiver),
                src_port=self.port_for(sender),
                dst_port=self.port_for(receiver),
                payload=payload,
                seq=seq,
                ack=ack,
                flags=flags,
                timestamp=timestamp,
            )
        )
        self.next_seq[sender] = (self.next_seq[sender] + len(payload)) & 0xFFFFFFFF
        self.peer_ack[receiver] = self.next_seq[sender]
        ack_seq = self.next_seq[receiver]
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(receiver),
                dst_ip=self.ip_for(sender),
                src_port=self.port_for(receiver),
                dst_port=self.port_for(sender),
                payload=b"",
                seq=ack_seq,
                ack=self.next_seq[sender],
                flags="A",
                timestamp=timestamp + self.config.ack_delta,
            )
        )
        return packets

    def fin_packets(self, timestamp: float, sender: str) -> List[PacketSpec]:
        packets: List[PacketSpec] = []
        receiver = self.other(sender)
        seq = self.next_seq[sender]
        ack = self.peer_ack.get(sender, self.next_seq[receiver])
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(sender),
                dst_ip=self.ip_for(receiver),
                src_port=self.port_for(sender),
                dst_port=self.port_for(receiver),
                payload=b"",
                seq=seq,
                ack=ack,
                flags="FA",
                timestamp=timestamp,
            )
        )
        self.next_seq[sender] = (self.next_seq[sender] + 1) & 0xFFFFFFFF
        self.peer_ack[receiver] = self.next_seq[sender]
        packets.append(
            PacketSpec(
                layer4="TCP",
                src_ip=self.ip_for(receiver),
                dst_ip=self.ip_for(sender),
                src_port=self.port_for(receiver),
                dst_port=self.port_for(sender),
                payload=b"",
                seq=self.next_seq[receiver],
                ack=self.next_seq[sender],
                flags="A",
                timestamp=timestamp + self.config.ack_delta,
            )
        )
        self.closed_sides.add(sender)
        return packets


@dataclass
class UnixDgramFlow:
    inode: int
    index: int
    config: UnixSynthConfig
    endpoints: Dict[EndpointKey, str] = field(default_factory=dict)
    path: Optional[str] = None

    def ip_for(self, side: str) -> str:
        if side == "A":
            return self.config.ip_for_a(self.index)
        return self.config.ip_for_b(self.index)

    def port_for(self, side: str) -> int:
        if side == "A":
            return self.config.sport_for_inode(self.inode)
        return self.config.dport_for_inode(self.inode)

    def assign_side(self, endpoint: EndpointKey) -> str:
        if endpoint in self.endpoints:
            return self.endpoints[endpoint]
        if not self.endpoints:
            side = "A"
        else:
            side = "B"
        self.endpoints[endpoint] = side
        return side

    def other(self, side: str) -> str:
        return "B" if side == "A" else "A"


class UnixFlowManager:
    """Track AF_UNIX endpoints and emit synthetic packets."""

    def __init__(self, config: UnixSynthConfig) -> None:
        self.config = config
        self.stream_flows: Dict[int, UnixStreamFlow] = {}
        self.dgram_flows: Dict[int, UnixDgramFlow] = {}
        self.order: Dict[int, int] = {}
        self._next_index = 0

    def _flow_index(self, inode: int) -> int:
        if inode not in self.order:
            self.order[inode] = self._next_index
            self._next_index += 1
        return self.order[inode]

    def _get_stream(self, inode: int, type_hint: Optional[str]) -> UnixStreamFlow:
        if inode not in self.stream_flows:
            flow = UnixStreamFlow(
                inode=inode,
                index=self._flow_index(inode),
                config=self.config,
                type_hint=type_hint,
            )
            self.stream_flows[inode] = flow
        else:
            flow = self.stream_flows[inode]
            if type_hint and not flow.type_hint:
                flow.type_hint = type_hint
        return flow

    def _get_dgram(self, inode: int) -> UnixDgramFlow:
        if inode not in self.dgram_flows:
            flow = UnixDgramFlow(
                inode=inode,
                index=self._flow_index(inode),
                config=self.config,
            )
            self.dgram_flows[inode] = flow
        else:
            flow = self.dgram_flows[inode]
        return flow

    def _endpoint_key(self, parsed) -> EndpointKey:
        return (parsed['pid'], parsed['fd'], parsed['session'])

    def handle_event(self, parsed) -> List[PacketSpec]:
        if not self.config.enable:
            return []
        protocol = parsed.get('protocol')
        inode = parsed.get('inode')
        if not inode or protocol not in ('UNIX', 'UNIX-STREAM', 'UNIX-DGRAM'):
            return []
        if protocol == 'UNIX-DGRAM':
            return self._handle_dgram(parsed)
        # treat plain UNIX as stream unless hint says otherwise
        if protocol == 'UNIX-STREAM' or parsed.get('unix_type_hint') == 'STREAM':
            return self._handle_stream(parsed, type_hint='STREAM')
        if parsed.get('unix_type_hint') == 'DGRAM':
            return self._handle_dgram(parsed)
        # default to stream
        return self._handle_stream(parsed, type_hint=parsed.get('unix_type_hint'))

    def _handle_stream(self, parsed, type_hint=None) -> List[PacketSpec]:
        inode = parsed['inode']
        flow = self._get_stream(inode, type_hint)
        endpoint = self._endpoint_key(parsed)
        syscall = parsed['syscall']
        if parsed.get('unix_path'):
            flow.set_path(parsed['unix_path'])
        result = parsed.get('result', 0)
        timestamp = parsed.get('time', 0.0)
        packets: List[PacketSpec] = []
        if syscall in ('socket', 'bind'):
            flow.assign_side(endpoint)
            return packets
        if syscall in ('connect',):
            flow.set_role_hint(endpoint, 'client')
            flow.assign_side(endpoint, prefer='A')
            return packets
        if syscall in ('accept', 'accept4'):
            flow.set_role_hint(endpoint, 'server')
            flow.assign_side(endpoint, prefer='B')
            return packets
        if syscall in ('close', 'shutdown'):
            side = flow.assign_side(endpoint)
            packets.extend(flow.fin_packets(timestamp, side))
            return packets
        if result is None or result <= 0:
            return []
        payload = parsed.get('payload', b'')
        if not payload:
            return packets
        side = flow.assign_side(endpoint)
        sender = side if parsed.get('direction_out') else flow.other(side)
        if not flow.handshake_done:
            packets.extend(flow.ensure_handshake(timestamp, sender))
        packets.extend(flow.data_packet(timestamp, sender, payload))
        return packets

    def _handle_dgram(self, parsed) -> List[PacketSpec]:
        inode = parsed['inode']
        flow = self._get_dgram(inode)
        endpoint = self._endpoint_key(parsed)
        if parsed.get('unix_path'):
            flow.path = parsed['unix_path']
        syscall = parsed['syscall']
        if syscall in ('socket', 'bind', 'connect', 'accept', 'accept4'):
            flow.assign_side(endpoint)
            return []
        if syscall in ('close', 'shutdown'):
            return []
        if parsed.get('result', 0) is None or parsed['result'] <= 0:
            return []
        payload = parsed.get('payload', b'')
        if not payload:
            return []
        side = flow.assign_side(endpoint)
        sender = side if parsed.get('direction_out') else flow.other(side)
        timestamp = parsed.get('time', 0.0)
        receiver = flow.other(sender)
        return [
            PacketSpec(
                layer4='UDP',
                src_ip=flow.ip_for(sender),
                dst_ip=flow.ip_for(receiver),
                src_port=flow.port_for(sender),
                dst_port=flow.port_for(receiver),
                payload=payload,
                timestamp=timestamp,
            )
        ]


def build_packet(spec: PacketSpec, linktype: str, ip_id: int):
    """Render PacketSpec to a scapy packet with timestamp set."""
    if spec.layer4 == 'TCP':
        pkt = IP(src=spec.src_ip, dst=spec.dst_ip, id=ip_id, ttl=64) / TCP(
            sport=spec.src_port,
            dport=spec.dst_port,
            seq=spec.seq,
            ack=spec.ack,
            flags=spec.flags,
        )
        if spec.payload:
            pkt = pkt / Raw(spec.payload)
    else:
        pkt = IP(src=spec.src_ip, dst=spec.dst_ip, id=ip_id, ttl=64) / UDP(
            sport=spec.src_port,
            dport=spec.dst_port,
        )
        if spec.payload:
            pkt = pkt / Raw(spec.payload)
    pkt.time = spec.timestamp
    if linktype == 'ether':
        ether = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
        ether.time = spec.timestamp
        return ether / pkt
    return pkt
