"""Shared framing and Fernet encryption helpers for chat clients and servers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
from pathlib import Path
from typing import Protocol, Sequence

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DEFAULT_KEY_FILE = "key.key"
DEFAULT_IDENTITY_STORE = Path(os.environ.get("ENCRYPTED_CHAT_IDENTITY_STORE", Path.home() / ".encrypted_chat" / "trusted_peers.json"))
DEFAULT_CLIENT_IDENTITY_FILE = Path(
    os.environ.get("ENCRYPTED_CHAT_CLIENT_IDENTITY", Path.home() / ".encrypted_chat" / "identity_ed25519.key")
)
DEFAULT_CLIENT_INBOX_FILE = Path(
    os.environ.get("ENCRYPTED_CHAT_CLIENT_INBOX", Path.home() / ".encrypted_chat" / "inbox_x25519.key")
)
MAX_FRAME_SIZE = 16 * 1024 * 1024
E2EE_INFO = b"encrypted-chat-e2ee-v1"
OFFLINE_INFO = b"encrypted-chat-offline-v1"
SAFETY_WORDS = (
    "amber",
    "bamboo",
    "copper",
    "delta",
    "ember",
    "forest",
    "galaxy",
    "harbor",
    "island",
    "jasmine",
    "kernel",
    "lantern",
    "magnet",
    "nebula",
    "onyx",
    "prairie",
    "quartz",
    "river",
    "signal",
    "topaz",
    "umbra",
    "velvet",
    "willow",
    "xenon",
    "yonder",
    "zenith",
)


class Cipher(Protocol):
    def encrypt(self, data: bytes) -> bytes: ...

    def decrypt(self, token: bytes) -> bytes: ...


class MultiLayerFernet:
    """Apply several Fernet keys as nested encryption layers."""

    def __init__(self, keys: Sequence[bytes]) -> None:
        if not keys:
            raise ValueError("at least one encryption key is required")
        self._layers = [Fernet(key) for key in keys]

    @property
    def layer_count(self) -> int:
        return len(self._layers)

    def encrypt(self, data: bytes) -> bytes:
        token = data
        for layer in self._layers:
            token = layer.encrypt(token)
        return token

    def decrypt(self, token: bytes) -> bytes:
        data = token
        for layer in reversed(self._layers):
            data = layer.decrypt(data)
        return data


def generate_e2ee_key_pair() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def load_or_create_identity_key(path: str | Path = DEFAULT_CLIENT_IDENTITY_FILE) -> ed25519.Ed25519PrivateKey:
    key_path = Path(path)
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_text(base64.urlsafe_b64encode(private_bytes).decode("ascii"), encoding="utf-8")
        return private_key
    private_bytes = base64.urlsafe_b64decode(key_path.read_text(encoding="utf-8").strip().encode("ascii"))
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)


def load_or_create_x25519_key(path: str | Path = DEFAULT_CLIENT_INBOX_FILE) -> x25519.X25519PrivateKey:
    key_path = Path(path)
    if not key_path.exists():
        key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key = x25519.X25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_text(base64.urlsafe_b64encode(private_bytes).decode("ascii"), encoding="utf-8")
        return private_key
    private_bytes = base64.urlsafe_b64decode(key_path.read_text(encoding="utf-8").strip().encode("ascii"))
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


def encode_identity_public_key(private_key: ed25519.Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(public_bytes).decode("ascii")


def encode_public_key(private_key: x25519.X25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(public_bytes).decode("ascii")


def decode_public_key(encoded: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(encoded.encode("ascii")))


def public_key_fingerprint(encoded: str) -> str:
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


def identity_safety_code(first_identity_public_key: str, second_identity_public_key: str) -> str:
    ordered = sorted((first_identity_public_key, second_identity_public_key))
    digest = hashlib.sha256("|".join(ordered).encode("ascii")).hexdigest()
    return "-".join(digest[i : i + 4] for i in range(0, 24, 4))


def identity_safety_phrase(first_identity_public_key: str, second_identity_public_key: str) -> str:
    ordered = sorted((first_identity_public_key, second_identity_public_key))
    digest = hashlib.sha256(("phrase|" + "|".join(ordered)).encode("ascii")).digest()
    words = [SAFETY_WORDS[value % len(SAFETY_WORDS)] for value in digest[:6]]
    return " ".join(words)


def sign_e2ee_hello(
    identity_key: ed25519.Ed25519PrivateKey,
    identity_public_key: str,
    ephemeral_public_key: str,
    inbox_public_key: str | None = None,
) -> str:
    if inbox_public_key is None:
        payload = f"HELLO2|{identity_public_key}|{ephemeral_public_key}".encode("ascii")
    else:
        payload = f"HELLO3|{identity_public_key}|{ephemeral_public_key}|{inbox_public_key}".encode("ascii")
    signature = identity_key.sign(payload)
    return base64.urlsafe_b64encode(signature).decode("ascii")


def build_e2ee_hello(
    identity_key: ed25519.Ed25519PrivateKey,
    ephemeral_private_key: x25519.X25519PrivateKey,
    inbox_private_key: x25519.X25519PrivateKey | None = None,
) -> str:
    identity_public_key = encode_identity_public_key(identity_key)
    ephemeral_public_key = encode_public_key(ephemeral_private_key)
    if inbox_private_key is None:
        signature = sign_e2ee_hello(identity_key, identity_public_key, ephemeral_public_key)
        return f"HELLO2|{identity_public_key}|{ephemeral_public_key}|{signature}"
    inbox_public_key = encode_public_key(inbox_private_key)
    signature = sign_e2ee_hello(identity_key, identity_public_key, ephemeral_public_key, inbox_public_key)
    return f"HELLO3|{identity_public_key}|{ephemeral_public_key}|{inbox_public_key}|{signature}"


def parse_e2ee_hello(text: str) -> tuple[str, str, str | None]:
    parts = text.split("|")
    if len(parts) == 4 and parts[0] == "HELLO2":
        _, identity_public_key, ephemeral_public_key, signature = parts
        signed_payload = f"HELLO2|{identity_public_key}|{ephemeral_public_key}".encode("ascii")
        inbox_public_key = None
    elif len(parts) == 5 and parts[0] == "HELLO3":
        _, identity_public_key, ephemeral_public_key, inbox_public_key, signature = parts
        signed_payload = f"HELLO3|{identity_public_key}|{ephemeral_public_key}|{inbox_public_key}".encode("ascii")
    else:
        raise ValueError("invalid E2EE hello")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(identity_public_key.encode("ascii"))
    )
    public_key.verify(
        base64.urlsafe_b64decode(signature.encode("ascii")),
        signed_payload,
    )
    return identity_public_key, ephemeral_public_key, inbox_public_key


def load_trusted_peers(path: str | Path = DEFAULT_IDENTITY_STORE) -> dict[str, str]:
    store_path = Path(path)
    if not store_path.exists():
        return {}
    with store_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("trusted peer store must contain an object")
    return {str(alias): str(fingerprint) for alias, fingerprint in data.items()}


def save_trusted_peer(alias: str, fingerprint: str, path: str | Path = DEFAULT_IDENTITY_STORE) -> None:
    store_path = Path(path)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    peers = load_trusted_peers(store_path)
    peers[alias] = fingerprint
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(peers, f, indent=2, sort_keys=True)


def remove_trusted_peer(alias: str, path: str | Path = DEFAULT_IDENTITY_STORE) -> bool:
    store_path = Path(path)
    peers = load_trusted_peers(store_path)
    removed = alias in peers
    peers.pop(alias, None)
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("w", encoding="utf-8") as f:
        json.dump(peers, f, indent=2, sort_keys=True)
    return removed


def create_e2ee_cipher(private_key: x25519.X25519PrivateKey, peer_public_key: str) -> Fernet:
    peer_public_bytes = base64.urlsafe_b64decode(peer_public_key.encode("ascii"))
    own_public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_salt = hashlib.sha256(b"".join(sorted((own_public_bytes, peer_public_bytes)))).digest()
    shared_secret = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_bytes))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_salt,
        info=E2EE_INFO,
    ).derive(shared_secret)
    return Fernet(base64.urlsafe_b64encode(derived_key))


def create_e2ee_session_cipher(
    ephemeral_private_key: x25519.X25519PrivateKey,
    peer_ephemeral_public_key: str,
    own_identity_public_key: str,
    peer_identity_public_key: str,
) -> Fernet:
    peer_public_bytes = base64.urlsafe_b64decode(peer_ephemeral_public_key.encode("ascii"))
    own_ephemeral_public_bytes = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_parts = sorted(
        [
            own_identity_public_key.encode("ascii"),
            peer_identity_public_key.encode("ascii"),
            base64.urlsafe_b64encode(own_ephemeral_public_bytes),
            peer_ephemeral_public_key.encode("ascii"),
        ]
    )
    transcript_salt = hashlib.sha256(b"|".join(transcript_parts)).digest()
    shared_secret = ephemeral_private_key.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public_bytes))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_salt,
        info=E2EE_INFO,
    ).derive(shared_secret)
    return Fernet(base64.urlsafe_b64encode(derived_key))


def create_offline_cipher_for_recipient(
    sender_ephemeral_private_key: x25519.X25519PrivateKey,
    recipient_inbox_public_key: str,
    sender_identity_public_key: str,
    recipient_identity_public_key: str,
) -> Fernet:
    sender_ephemeral_public = encode_public_key(sender_ephemeral_private_key)
    transcript_salt = hashlib.sha256(
        b"|".join(
            sorted(
                [
                    sender_identity_public_key.encode("ascii"),
                    recipient_identity_public_key.encode("ascii"),
                    sender_ephemeral_public.encode("ascii"),
                    recipient_inbox_public_key.encode("ascii"),
                ]
            )
        )
    ).digest()
    shared_secret = sender_ephemeral_private_key.exchange(decode_public_key(recipient_inbox_public_key))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_salt,
        info=OFFLINE_INFO,
    ).derive(shared_secret)
    return Fernet(base64.urlsafe_b64encode(derived_key))


def create_offline_cipher_for_recipient_private_key(
    recipient_inbox_private_key: x25519.X25519PrivateKey,
    sender_ephemeral_public_key: str,
    sender_identity_public_key: str,
    recipient_identity_public_key: str,
) -> Fernet:
    recipient_inbox_public_key = encode_public_key(recipient_inbox_private_key)
    transcript_salt = hashlib.sha256(
        b"|".join(
            sorted(
                [
                    sender_identity_public_key.encode("ascii"),
                    recipient_identity_public_key.encode("ascii"),
                    sender_ephemeral_public_key.encode("ascii"),
                    recipient_inbox_public_key.encode("ascii"),
                ]
            )
        )
    ).digest()
    shared_secret = recipient_inbox_private_key.exchange(decode_public_key(sender_ephemeral_public_key))
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_salt,
        info=OFFLINE_INFO,
    ).derive(shared_secret)
    return Fernet(base64.urlsafe_b64encode(derived_key))


def load_or_create_key(path: str | Path = DEFAULT_KEY_FILE) -> bytes:
    key_path = Path(path)
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    return key_path.read_bytes()


def create_cipher(paths: str | Path | Sequence[str | Path] = DEFAULT_KEY_FILE) -> Cipher:
    if isinstance(paths, str | Path):
        key_paths = [paths]
    else:
        key_paths = list(paths)
    return MultiLayerFernet([load_or_create_key(path) for path in key_paths])


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > MAX_FRAME_SIZE:
        raise ValueError(f"frame too large: {len(data)}")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    (size,) = struct.unpack("!I", recv_exact(sock, 4))
    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ValueError(f"invalid frame size: {size}")
    return recv_exact(sock, size)


def send_encrypted(sock: socket.socket, cipher: Cipher, data: bytes) -> None:
    encrypted = cipher.encrypt(data)
    send_frame(sock, encrypted)


def recv_encrypted(sock: socket.socket, cipher: Cipher) -> bytes:
    return cipher.decrypt(recv_frame(sock))
