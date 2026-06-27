"""Direct LAN peer listener and connector foundation."""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass
from typing import Callable

try:
    from .transport import SocketTransport
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from transport import SocketTransport


@dataclass(frozen=True)
class DirectPeerEndpoint:
    host: str
    port: int


class DirectPeerListener:
    def __init__(
        self,
        host: str,
        port: int,
        on_peer: Callable[[SocketTransport], None],
        name: str = "lan-direct",
    ) -> None:
        self.host = host
        self.port = port
        self.on_peer = on_peer
        self.name = name
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint(self) -> DirectPeerEndpoint:
        if self._server_socket is None:
            return DirectPeerEndpoint(self.host, self.port)
        host, port = self._server_socket.getsockname()
        return DirectPeerEndpoint(host, port)

    def start(self) -> DirectPeerEndpoint:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen()
        server_socket.settimeout(0.25)
        self._server_socket = server_socket

        def run() -> None:
            try:
                while not self._stop_event.is_set():
                    try:
                        conn, _ = server_socket.accept()
                    except socket.timeout:
                        continue
                    self.on_peer(SocketTransport(conn, name=self.name))
            finally:
                server_socket.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        return self.endpoint

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)


def connect_direct_peer(host: str, port: int, timeout: float | None = None) -> SocketTransport:
    sock = socket.create_connection((host, port), timeout=timeout)
    return SocketTransport(sock, name="lan-direct")
