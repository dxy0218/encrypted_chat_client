"""E2EE session, identity, and trust management."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

try:
    from .padding import pad_payload, unpad_payload
    from .protocol import (
        Cipher,
        build_e2ee_hello,
        create_e2ee_session_cipher,
        create_offline_cipher_for_recipient,
        create_offline_cipher_for_recipient_private_key,
        encode_identity_public_key,
        encode_public_key,
        generate_e2ee_key_pair,
        identity_safety_code,
        identity_safety_phrase,
        load_or_create_identity_key,
        load_or_create_x25519_key,
        load_trusted_peers,
        parse_e2ee_hello,
        public_key_fingerprint,
        remove_trusted_peer,
        save_trusted_peer,
    )
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from padding import pad_payload, unpad_payload
    from protocol import (
        Cipher,
        build_e2ee_hello,
        create_e2ee_session_cipher,
        create_offline_cipher_for_recipient,
        create_offline_cipher_for_recipient_private_key,
        encode_identity_public_key,
        encode_public_key,
        generate_e2ee_key_pair,
        identity_safety_code,
        identity_safety_phrase,
        load_or_create_identity_key,
        load_or_create_x25519_key,
        load_trusted_peers,
        parse_e2ee_hello,
        public_key_fingerprint,
        remove_trusted_peer,
        save_trusted_peer,
    )


@dataclass(frozen=True)
class PeerSessionInfo:
    fingerprint: str
    safety_code: str
    safety_phrase: str
    identity_verified: bool
    inbox_available: bool


class E2EESession:
    """Owns persistent identity, ephemeral session keys, and peer trust state."""

    def __init__(
        self,
        identity_key_path: Path,
        identity_store: Path,
        peer_alias: str,
        pad_payloads: bool = False,
        inbox_key_path: Path | None = None,
    ) -> None:
        self.identity_store = identity_store
        self.peer_alias = peer_alias
        self.pad_payloads = pad_payloads
        self.ephemeral_private_key = generate_e2ee_key_pair()
        self.identity_key = load_or_create_identity_key(identity_key_path)
        self.inbox_private_key = load_or_create_x25519_key(
            inbox_key_path or identity_key_path.with_name("inbox_x25519.key")
        )
        self.identity_public_key = encode_identity_public_key(self.identity_key)
        self.inbox_public_key = encode_public_key(self.inbox_private_key)
        self.hello = build_e2ee_hello(self.identity_key, self.ephemeral_private_key, self.inbox_private_key)

        self.cipher: Cipher | None = None
        self.peer_identity_public_key: str | None = None
        self.peer_inbox_public_key: str | None = None
        self.peer_fingerprint: str | None = None
        self.safety_code: str | None = None
        self.safety_phrase: str | None = None
        self.identity_verified = False
        self.unverified_sent = 0
        self.ready = threading.Event()
        self.lock = threading.Lock()

    @property
    def own_fingerprint(self) -> str:
        return public_key_fingerprint(self.identity_public_key)

    def process_hello(self, hello_text: str) -> PeerSessionInfo | None:
        peer_identity_public_key, peer_ephemeral_public_key, peer_inbox_public_key = parse_e2ee_hello(hello_text)
        if peer_identity_public_key == self.identity_public_key:
            return None

        with self.lock:
            self.cipher = create_e2ee_session_cipher(
                self.ephemeral_private_key,
                peer_ephemeral_public_key,
                self.identity_public_key,
                peer_identity_public_key,
            )
            self.peer_identity_public_key = peer_identity_public_key
            self.peer_inbox_public_key = peer_inbox_public_key
            self.peer_fingerprint = public_key_fingerprint(peer_identity_public_key)
            self.safety_code = identity_safety_code(self.identity_public_key, peer_identity_public_key)
            self.safety_phrase = identity_safety_phrase(self.identity_public_key, peer_identity_public_key)
            self.identity_verified = (
                load_trusted_peers(self.identity_store).get(self.peer_alias) == self.peer_fingerprint
            )
            self.ready.set()

        return PeerSessionInfo(
            fingerprint=self.peer_fingerprint,
            safety_code=self.safety_code,
            safety_phrase=self.safety_phrase,
            identity_verified=self.identity_verified,
            inbox_available=self.peer_inbox_public_key is not None,
        )

    def encrypt_payload(self, data: bytes) -> bytes:
        if self.cipher is None:
            raise RuntimeError("end-to-end session is not ready")
        if self.pad_payloads:
            data = pad_payload(data)
        return b"E2EE|" + self.cipher.encrypt(data)

    def decrypt_payload_frame(self, frame: bytes) -> bytes:
        if self.cipher is None:
            raise RuntimeError("end-to-end session is not ready")
        if not frame.startswith(b"E2EE|"):
            raise ValueError("not an E2EE payload frame")
        data = self.cipher.decrypt(frame.split(b"|", 1)[1])
        if self.pad_payloads:
            data = unpad_payload(data)
        return data

    def encrypt_offline_payload(self, data: bytes) -> bytes:
        if self.peer_identity_public_key is None or self.peer_inbox_public_key is None:
            raise RuntimeError("peer inbox key is not available")
        sender_ephemeral_private_key = generate_e2ee_key_pair()
        sender_ephemeral_public_key = encode_public_key(sender_ephemeral_private_key)
        cipher = create_offline_cipher_for_recipient(
            sender_ephemeral_private_key,
            self.peer_inbox_public_key,
            self.identity_public_key,
            self.peer_identity_public_key,
        )
        token = cipher.encrypt(data)
        return b"OFFE2EE|" + "|".join(
            [
                self.identity_public_key,
                sender_ephemeral_public_key,
                token.decode("ascii"),
            ]
        ).encode("ascii")

    def decrypt_offline_payload(self, frame: bytes) -> bytes:
        text = frame.decode("ascii")
        parts = text.split("|", 3)
        if len(parts) != 4 or parts[0] != "OFFE2EE":
            raise ValueError("not an offline E2EE frame")
        _, sender_identity_public_key, sender_ephemeral_public_key, token = parts
        cipher = create_offline_cipher_for_recipient_private_key(
            self.inbox_private_key,
            sender_ephemeral_public_key,
            sender_identity_public_key,
            self.identity_public_key,
        )
        return cipher.decrypt(token.encode("ascii"))

    def trust_peer(self) -> str:
        if self.peer_fingerprint is None:
            raise RuntimeError("no peer fingerprint available yet")
        save_trusted_peer(self.peer_alias, self.peer_fingerprint, self.identity_store)
        self.identity_verified = True
        return self.peer_fingerprint

    def untrust_peer(self) -> bool:
        self.identity_verified = False
        return remove_trusted_peer(self.peer_alias, self.identity_store)

    def reject_peer(self) -> None:
        self.identity_verified = False
