"""Durable encrypted packet store for offline delivery workflows."""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class StoredPacket:
    packet_id: str
    payload: bytes
    expires_at: float
    created_at: float
    recipient: str = ""

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class OfflinePacketStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def add(
        self,
        payload: bytes,
        ttl_seconds: float,
        packet_id: str | None = None,
        recipient: str = "",
    ) -> StoredPacket:
        now = time.time()
        packet = StoredPacket(
            packet_id=packet_id or str(uuid.uuid4()),
            payload=payload,
            created_at=now,
            expires_at=now + ttl_seconds,
            recipient=recipient,
        )
        packets = {
            (existing.recipient, existing.packet_id): existing
            for existing in self.load_all(include_expired=True)
        }
        packets[(packet.recipient, packet.packet_id)] = packet
        self._write_all(list(packets.values()))
        return packet

    def load_all(self, include_expired: bool = False) -> list[StoredPacket]:
        if not self.path.exists():
            return []
        packets: list[StoredPacket] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            packet = StoredPacket(
                packet_id=str(payload["packet_id"]),
                payload=base64.b64decode(str(payload["payload"]).encode("ascii")),
                created_at=float(payload["created_at"]),
                expires_at=float(payload["expires_at"]),
                recipient=str(payload.get("recipient", "")),
            )
            if include_expired or not packet.expired:
                packets.append(packet)
        return packets

    def load_for_recipient(self, recipient: str, include_expired: bool = False) -> list[StoredPacket]:
        return [
            packet
            for packet in self.load_all(include_expired=include_expired)
            if packet.recipient == recipient
        ]

    def prune_expired(self) -> int:
        packets = self.load_all(include_expired=True)
        live_packets = [packet for packet in packets if not packet.expired]
        self._write_all(live_packets)
        return len(packets) - len(live_packets)

    def remove(self, packet_id: str, recipient: str | None = None) -> bool:
        packets = self.load_all(include_expired=True)
        kept = [
            packet
            for packet in packets
            if not (packet.packet_id == packet_id and (recipient is None or packet.recipient == recipient))
        ]
        self._write_all(kept)
        return len(kept) != len(packets)

    def _write_all(self, packets: list[StoredPacket]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(
                {
                    "packet_id": packet.packet_id,
                    "payload": base64.b64encode(packet.payload).decode("ascii"),
                    "recipient": packet.recipient,
                    "created_at": packet.created_at,
                    "expires_at": packet.expires_at,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            for packet in packets
        ]
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
