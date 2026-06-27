"""UDP LAN discovery for local relay endpoints."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass


DISCOVERY_MAGIC = "encrypted-chat-relay-v1"
DEFAULT_DISCOVERY_PORT = 45454


@dataclass(frozen=True)
class LanEndpoint:
    host: str
    port: int
    mode: str


def build_advertisement(host: str, port: int, mode: str) -> bytes:
    return json.dumps(
        {"magic": DISCOVERY_MAGIC, "host": host, "port": port, "mode": mode},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_advertisement(data: bytes) -> LanEndpoint | None:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if payload.get("magic") != DISCOVERY_MAGIC:
        return None
    host = payload.get("host")
    port = payload.get("port")
    mode = payload.get("mode")
    if not isinstance(host, str) or not isinstance(port, int) or not isinstance(mode, str):
        return None
    if port <= 0 or port > 65535:
        return None
    return LanEndpoint(host=host, port=port, mode=mode)


def start_lan_advertiser(
    host: str,
    port: int,
    mode: str,
    stop_event: threading.Event,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
    interval_seconds: float = 2.0,
) -> threading.Thread:
    def run() -> None:
        message = build_advertisement(host, port, mode)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while not stop_event.is_set():
                sock.sendto(message, ("255.255.255.255", discovery_port))
                stop_event.wait(interval_seconds)
        finally:
            sock.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def discover_lan_relay(
    timeout_seconds: float = 3.0,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
    expected_mode: str | None = None,
) -> LanEndpoint | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", discovery_port))
        sock.settimeout(0.25)
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                continue
            endpoint = parse_advertisement(data)
            if endpoint is None:
                continue
            if expected_mode is not None and endpoint.mode != expected_mode:
                continue
            return endpoint
        return None
    finally:
        sock.close()
