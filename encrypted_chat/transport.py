"""Transport abstractions for relay, LAN, and future store-and-forward paths."""

from __future__ import annotations

import socket
from dataclasses import dataclass

try:
    from .protocol import Cipher, recv_encrypted, recv_frame, send_encrypted, send_frame
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from protocol import Cipher, recv_encrypted, recv_frame, send_encrypted, send_frame


@dataclass(frozen=True)
class TransportInfo:
    name: str
    peer: str


class SocketTransport:
    """Length-prefixed frame transport over a connected socket."""

    def __init__(self, sock: socket.socket, name: str = "tcp") -> None:
        self.sock = sock
        self.name = name

    @property
    def info(self) -> TransportInfo:
        try:
            peer = f"{self.sock.getpeername()[0]}:{self.sock.getpeername()[1]}"
        except OSError:
            peer = "disconnected"
        return TransportInfo(name=self.name, peer=peer)

    def send_frame(self, data: bytes) -> None:
        send_frame(self.sock, data)

    def recv_frame(self) -> bytes:
        return recv_frame(self.sock)

    def send_encrypted(self, cipher: Cipher, data: bytes) -> None:
        send_encrypted(self.sock, cipher, data)

    def recv_encrypted(self, cipher: Cipher) -> bytes:
        return recv_encrypted(self.sock, cipher)

    def close(self) -> None:
        self.sock.close()


def connect_tcp(host: str, port: int, timeout: float | None = None, name: str = "relay") -> SocketTransport:
    sock = socket.create_connection((host, port), timeout=timeout)
    return SocketTransport(sock, name=name)
