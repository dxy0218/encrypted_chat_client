"""Payload padding helpers to reduce message size leakage."""

from __future__ import annotations

import os
import struct


DEFAULT_PADDING_BUCKETS = (256, 512, 1024, 2048, 4096, 8192, 16384)


def next_bucket(size: int, buckets: tuple[int, ...] = DEFAULT_PADDING_BUCKETS) -> int:
    for bucket in buckets:
        if size <= bucket:
            return bucket
    return size


def pad_payload(payload: bytes, buckets: tuple[int, ...] = DEFAULT_PADDING_BUCKETS) -> bytes:
    header_size = 4
    target_size = next_bucket(len(payload) + header_size, buckets)
    padding_size = target_size - header_size - len(payload)
    return struct.pack("!I", len(payload)) + payload + os.urandom(padding_size)


def unpad_payload(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise ValueError("padded payload is too short")
    (payload_size,) = struct.unpack("!I", padded[:4])
    if payload_size > len(padded) - 4:
        raise ValueError("invalid padded payload size")
    return padded[4 : 4 + payload_size]
