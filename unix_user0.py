"""Emit AF_UNIX events as USER0 (UXSO) records."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from scapy.all import Raw
from scapy.config import conf


conf.l2types.register(147, Raw)


UXSO_MAGIC = b"UXSO"
UXSO_VERSION = 1
UXSO_STREAM = 1
UXSO_DGRAM = 2

UXSO_DIR_UNKNOWN = 0
UXSO_DIR_WRITE = 1
UXSO_DIR_READ = 2

_SYS_OUT = {"write", "sendto", "sendmsg"}
_SYS_IN = {"read", "recvfrom", "recvmsg"}


@dataclass
class UnixSocketInfo:
    """Metadata collected for a UNIX socket inode."""

    stream_id: int
    path: Optional[str] = None
    peer_path: Optional[str] = None
    sock_type: int = UXSO_STREAM


class UnixUser0Emitter:
    """Convert parsed AF_UNIX events into UXSO USER0 frames."""

    def __init__(self, *, include_paths: bool = True) -> None:
        self.include_paths = include_paths
        self._next_stream_id = 1
        self._sockets: Dict[Tuple[str, int, int, int], UnixSocketInfo] = {}

    def has_split_cache(self):
        return False

    def get_split_cache(self):
        return False

    def _allocate_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id += 1
        return sid

    def _key_for_event(self, event) -> Tuple[str, int, int, int]:
        inode = event.get("inode")
        if inode:
            return ("inode", int(inode), 0, 0)
        pid = event.get("pid") or 0
        fd = event.get("fd")
        if isinstance(fd, int):
            session = event.get("session") or 0
            return ("pfd", int(pid), int(fd), int(session))
        return ("pid", int(pid), 0, 0)

    def _info_for_event(self, event) -> UnixSocketInfo:
        key = self._key_for_event(event)
        info = self._sockets.get(key)
        if info is None:
            info = UnixSocketInfo(stream_id=self._allocate_stream_id())
            self._sockets[key] = info
        return info

    def _sock_type_from_event(self, event, info: UnixSocketInfo) -> int:
        protocol = event.get("protocol", "")
        if protocol == "UNIX-DGRAM":
            info.sock_type = UXSO_DGRAM
        elif protocol in {"UNIX", "UNIX-STREAM"}:
            info.sock_type = UXSO_STREAM
        else:
            hint = event.get("unix_type_hint")
            if hint == "DGRAM":
                info.sock_type = UXSO_DGRAM
            elif hint == "STREAM":
                info.sock_type = UXSO_STREAM
        return info.sock_type

    def _update_paths(self, event, info: UnixSocketInfo) -> None:
        path = event.get("unix_path")
        if not path:
            return
        syscall = event.get("syscall")
        if syscall in {"bind", "accept", "accept4"}:
            info.path = path
        elif syscall == "connect":
            info.peer_path = path
        else:
            if info.path is None:
                info.path = path

    def _direction_for_syscall(self, syscall: str) -> int:
        if syscall in _SYS_OUT:
            return UXSO_DIR_WRITE
        if syscall in _SYS_IN:
            return UXSO_DIR_READ
        return UXSO_DIR_UNKNOWN

    def _build_record(self, event, info: UnixSocketInfo) -> bytes:
        syscall = event.get("syscall", "")
        direction = self._direction_for_syscall(syscall)
        sock_type = self._sock_type_from_event(event, info)
        pid = int(event.get("pid") or 0)
        fd = event.get("fd")
        if not isinstance(fd, int):
            fd_value = 0xFFFFFFFF
        else:
            fd_value = fd & 0xFFFFFFFF
        inode = event.get("inode")
        inode_value = int(inode) if inode else 0
        payload: bytes = event.get("payload") or b""
        flags = 0
        extra = b""
        if self.include_paths:
            if info.path:
                flags |= 0x01
                extra += info.path.encode("utf-8", "replace") + b"\x00"
            if info.peer_path:
                flags |= 0x02
                extra += info.peer_path.encode("utf-8", "replace") + b"\x00"
        header = struct.pack(
            "<4sBBBBIIIII",
            UXSO_MAGIC,
            UXSO_VERSION,
            sock_type,
            direction,
            flags,
            pid & 0xFFFFFFFF,
            fd_value,
            inode_value & 0xFFFFFFFF,
            info.stream_id & 0xFFFFFFFF,
            len(payload),
        )
        return header + extra + payload

    def process(self, event):
        if not event:
            return False
        protocol = event.get("protocol")
        if not protocol or not protocol.startswith("UNIX"):
            return False
        info = self._info_for_event(event)
        self._sock_type_from_event(event, info)
        self._update_paths(event, info)
        syscall = event.get("syscall", "")
        if syscall not in _SYS_OUT and syscall not in _SYS_IN:
            return False
        record = self._build_record(event, info)
        packet = Raw(record)
        packet.time = event.get("time", 0.0)
        return packet
