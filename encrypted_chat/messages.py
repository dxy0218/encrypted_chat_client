"""Message constants and small formatting helpers."""

from __future__ import annotations

import base64


UNVERIFIED_LIMIT = 5
UNVERIFIED_WARNING = "[UNVERIFIED IDENTITY - authenticity uncertain]"


def msg(message_id: int, content: str) -> str:
    return f"MSG|{message_id}|{content}"


def read(message_id: str | int) -> str:
    return f"READ|{message_id}"


def recall(message_id: str | int) -> str:
    return f"RECALL|{message_id}"


def file_header(filename: str, size: int) -> str:
    return f"FILE|{filename}|{size}"


def ping(timestamp: str) -> str:
    return f"PING|{timestamp}"


def pong(timestamp: str) -> str:
    return f"PONG|{timestamp}"


def store_packet(recipient: str, ttl_seconds: int, packet_id: str, payload: bytes) -> str:
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii")
    return f"STORE|{recipient}|{ttl_seconds}|{packet_id}|{encoded_payload}"


def parse_store_packet(text: str) -> tuple[str, int, str, bytes]:
    _, recipient, ttl, packet_id, encoded_payload = text.split("|", 4)
    return recipient, int(ttl), packet_id, base64.urlsafe_b64decode(encoded_payload.encode("ascii"))


def fetch_packets(recipient: str) -> str:
    return f"FETCH|{recipient}"


def stored_packet(packet_id: str, payload: bytes) -> str:
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii")
    return f"STORED|{packet_id}|{encoded_payload}"


def parse_stored_packet(text: str) -> tuple[str, bytes]:
    _, packet_id, encoded_payload = text.split("|", 2)
    return packet_id, base64.urlsafe_b64decode(encoded_payload.encode("ascii"))


def ack_packet(packet_id: str) -> str:
    return f"ACK|{packet_id}"


def mark_unverified(content: str) -> str:
    return f"{UNVERIFIED_WARNING} {content}"


def strip_unverified(content: str) -> tuple[bool, str]:
    if content.startswith(UNVERIFIED_WARNING):
        return True, content.removeprefix(UNVERIFIED_WARNING).lstrip()
    return False, content
