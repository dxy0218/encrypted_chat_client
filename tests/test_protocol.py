from __future__ import annotations

import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "encrypted_chat"))

from cryptography.fernet import Fernet

from contacts import ContactBook
from direct_peer import DirectPeerListener, connect_direct_peer
from lan_discovery import build_advertisement, parse_advertisement
from protocol import (
    MAX_FRAME_SIZE,
    build_e2ee_hello,
    create_cipher,
    create_e2ee_cipher,
    create_offline_cipher_for_recipient,
    create_offline_cipher_for_recipient_private_key,
    create_e2ee_session_cipher,
    encode_identity_public_key,
    encode_public_key,
    generate_e2ee_key_pair,
    identity_safety_code,
    identity_safety_phrase,
    load_or_create_identity_key,
    load_or_create_x25519_key,
    load_trusted_peers,
    parse_e2ee_hello,
    recv_encrypted,
    recv_frame,
    remove_trusted_peer,
    save_trusted_peer,
    send_encrypted,
    send_frame,
)
from messages import (
    UNVERIFIED_WARNING,
    fetch_packets,
    mark_unverified,
    msg,
    parse_stored_packet,
    parse_store_packet,
    read,
    store_packet,
    strip_unverified,
)
from message_queue import MessageQueue
from offline_store import OfflinePacketStore
from padding import pad_payload, unpad_payload
from session import E2EESession
from transport import SocketTransport


class ProtocolTest(unittest.TestCase):
    def test_send_and_receive_encrypted_frame(self) -> None:
        cipher = Fernet(Fernet.generate_key())
        left, right = socket.socketpair()
        try:
            send_encrypted(left, cipher, b"hello")
            self.assertEqual(recv_encrypted(right, cipher), b"hello")
        finally:
            left.close()
            right.close()

    def test_rejects_oversized_frame(self) -> None:
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack("!I", MAX_FRAME_SIZE + 1))
            with self.assertRaises(ValueError):
                recv_encrypted(right, Fernet(Fernet.generate_key()))
        finally:
            left.close()
            right.close()

    def test_create_cipher_creates_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "key.key"
            cipher = create_cipher(key_file)
            self.assertTrue(key_file.exists())
            token = cipher.encrypt(b"message")
            self.assertEqual(Fernet(key_file.read_bytes()).decrypt(token), b"message")

    def test_multi_layer_cipher_round_trips_with_matching_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_files = [Path(tmp) / "outer.key", Path(tmp) / "inner.key"]
            cipher = create_cipher(key_files)
            token = cipher.encrypt(b"layered message")
            self.assertEqual(cipher.decrypt(token), b"layered message")

    def test_multi_layer_cipher_requires_all_layers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_files = [Path(tmp) / "outer.key", Path(tmp) / "inner.key"]
            cipher = create_cipher(key_files)
            single_layer = Fernet(key_files[0].read_bytes())
            token = cipher.encrypt(b"layered message")
            with self.assertRaises(Exception):
                single_layer.decrypt(token)

    def test_raw_frame_round_trip(self) -> None:
        left, right = socket.socketpair()
        try:
            send_frame(left, b"HELLO|public-key")
            self.assertEqual(recv_frame(right), b"HELLO|public-key")
        finally:
            left.close()
            right.close()

    def test_e2ee_cipher_round_trips_between_peers(self) -> None:
        alice_private = generate_e2ee_key_pair()
        bob_private = generate_e2ee_key_pair()
        alice_public = encode_public_key(alice_private)
        bob_public = encode_public_key(bob_private)

        alice_cipher = create_e2ee_cipher(alice_private, bob_public)
        bob_cipher = create_e2ee_cipher(bob_private, alice_public)

        token = alice_cipher.encrypt(b"secret")
        self.assertEqual(bob_cipher.decrypt(token), b"secret")

    def test_e2ee_cipher_rejects_non_peer_key(self) -> None:
        alice_private = generate_e2ee_key_pair()
        bob_private = generate_e2ee_key_pair()
        mallory_private = generate_e2ee_key_pair()

        alice_cipher = create_e2ee_cipher(alice_private, encode_public_key(bob_private))
        mallory_cipher = create_e2ee_cipher(mallory_private, encode_public_key(alice_private))

        token = alice_cipher.encrypt(b"secret")
        with self.assertRaises(Exception):
            mallory_cipher.decrypt(token)

    def test_identity_key_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            identity_file = Path(tmp) / "identity.key"
            first = encode_identity_public_key(load_or_create_identity_key(identity_file))
            second = encode_identity_public_key(load_or_create_identity_key(identity_file))
            self.assertEqual(first, second)

    def test_x25519_key_persists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inbox_file = Path(tmp) / "inbox.key"
            first = encode_public_key(load_or_create_x25519_key(inbox_file))
            second = encode_public_key(load_or_create_x25519_key(inbox_file))
            self.assertEqual(first, second)

    def test_signed_e2ee_hello_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            identity_key = load_or_create_identity_key(Path(tmp) / "identity.key")
            ephemeral_key = generate_e2ee_key_pair()
            inbox_key = load_or_create_x25519_key(Path(tmp) / "inbox.key")
            hello = build_e2ee_hello(identity_key, ephemeral_key, inbox_key)
            identity_public, ephemeral_public, inbox_public = parse_e2ee_hello(hello)
            self.assertEqual(identity_public, encode_identity_public_key(identity_key))
            self.assertEqual(ephemeral_public, encode_public_key(ephemeral_key))
            self.assertEqual(inbox_public, encode_public_key(inbox_key))

    def test_signed_e2ee_hello2_still_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            identity_key = load_or_create_identity_key(Path(tmp) / "identity.key")
            ephemeral_key = generate_e2ee_key_pair()
            hello = build_e2ee_hello(identity_key, ephemeral_key)
            identity_public, ephemeral_public, inbox_public = parse_e2ee_hello(hello)
            self.assertEqual(identity_public, encode_identity_public_key(identity_key))
            self.assertEqual(ephemeral_public, encode_public_key(ephemeral_key))
            self.assertIsNone(inbox_public)

    def test_signed_e2ee_hello_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            identity_key = load_or_create_identity_key(Path(tmp) / "identity.key")
            hello = build_e2ee_hello(identity_key, generate_e2ee_key_pair())
            parts = hello.split("|")
            parts[2] = encode_public_key(generate_e2ee_key_pair())
            with self.assertRaises(Exception):
                parse_e2ee_hello("|".join(parts))

    def test_signed_identity_session_cipher_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice_identity = load_or_create_identity_key(Path(tmp) / "alice.key")
            bob_identity = load_or_create_identity_key(Path(tmp) / "bob.key")
            alice_ephemeral = generate_e2ee_key_pair()
            bob_ephemeral = generate_e2ee_key_pair()

            alice_identity_public = encode_identity_public_key(alice_identity)
            bob_identity_public = encode_identity_public_key(bob_identity)
            alice_ephemeral_public = encode_public_key(alice_ephemeral)
            bob_ephemeral_public = encode_public_key(bob_ephemeral)

            alice_cipher = create_e2ee_session_cipher(
                alice_ephemeral,
                bob_ephemeral_public,
                alice_identity_public,
                bob_identity_public,
            )
            bob_cipher = create_e2ee_session_cipher(
                bob_ephemeral,
                alice_ephemeral_public,
                bob_identity_public,
                alice_identity_public,
            )

            token = alice_cipher.encrypt(b"identity-bound secret")
            self.assertEqual(bob_cipher.decrypt(token), b"identity-bound secret")

    def test_trusted_peer_store_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "trusted.json"
            save_trusted_peer("alice", "abcd:1234", store)
            self.assertEqual(load_trusted_peers(store), {"alice": "abcd:1234"})

    def test_missing_trusted_peer_store_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_trusted_peers(Path(tmp) / "missing.json"), {})

    def test_remove_trusted_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "trusted.json"
            save_trusted_peer("alice", "abcd:1234", store)
            self.assertTrue(remove_trusted_peer("alice", store))
            self.assertEqual(load_trusted_peers(store), {})
            self.assertFalse(remove_trusted_peer("alice", store))

    def test_identity_safety_code_and_phrase_are_order_independent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = encode_identity_public_key(load_or_create_identity_key(Path(tmp) / "alice.key"))
            bob = encode_identity_public_key(load_or_create_identity_key(Path(tmp) / "bob.key"))
            self.assertEqual(identity_safety_code(alice, bob), identity_safety_code(bob, alice))
            self.assertEqual(identity_safety_phrase(alice, bob), identity_safety_phrase(bob, alice))

    def test_identity_safety_phrase_changes_for_different_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice = encode_identity_public_key(load_or_create_identity_key(Path(tmp) / "alice.key"))
            bob = encode_identity_public_key(load_or_create_identity_key(Path(tmp) / "bob.key"))
            carol = encode_identity_public_key(load_or_create_identity_key(Path(tmp) / "carol.key"))
            self.assertNotEqual(identity_safety_phrase(alice, bob), identity_safety_phrase(alice, carol))

    def test_message_helpers(self) -> None:
        self.assertEqual(msg(7, "hello"), "MSG|7|hello")
        self.assertEqual(read(7), "READ|7")
        marked = mark_unverified("hello")
        self.assertTrue(marked.startswith(UNVERIFIED_WARNING))
        self.assertEqual(strip_unverified(marked), (True, "hello"))
        self.assertEqual(strip_unverified("hello"), (False, "hello"))
        stored = store_packet("recipient-fp", 60, "packet-1", b"ciphertext")
        self.assertEqual(parse_store_packet(stored), ("recipient-fp", 60, "packet-1", b"ciphertext"))
        self.assertEqual(fetch_packets("recipient-fp"), "FETCH|recipient-fp")

    def test_e2ee_session_process_hello_and_trust(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            alice = E2EESession(tmp_path / "alice.key", tmp_path / "alice_trust.json", "bob")
            bob = E2EESession(tmp_path / "bob.key", tmp_path / "bob_trust.json", "alice")

            alice_info = alice.process_hello(bob.hello)
            bob_info = bob.process_hello(alice.hello)

            self.assertIsNotNone(alice_info)
            self.assertIsNotNone(bob_info)
            self.assertEqual(alice_info.safety_phrase, bob_info.safety_phrase)
            self.assertFalse(alice_info.identity_verified)

            token = alice.encrypt_payload(b"session payload")
            self.assertEqual(bob.decrypt_payload_frame(token), b"session payload")

            trusted = alice.trust_peer()
            self.assertEqual(load_trusted_peers(tmp_path / "alice_trust.json")["bob"], trusted)
            self.assertTrue(alice.untrust_peer())

    def test_e2ee_session_optional_padding_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            alice = E2EESession(tmp_path / "alice.key", tmp_path / "alice_trust.json", "bob", pad_payloads=True)
            bob = E2EESession(tmp_path / "bob.key", tmp_path / "bob_trust.json", "alice", pad_payloads=True)
            alice.process_hello(bob.hello)
            bob.process_hello(alice.hello)

            frame = alice.encrypt_payload(b"short")
            self.assertNotIn(b"short", frame)
            self.assertEqual(bob.decrypt_payload_frame(frame), b"short")

    def test_e2ee_session_offline_payload_survives_recipient_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            alice = E2EESession(tmp_path / "alice.key", tmp_path / "alice_trust.json", "bob")
            bob = E2EESession(tmp_path / "bob.key", tmp_path / "bob_trust.json", "alice")
            alice.process_hello(bob.hello)

            offline_frame = alice.encrypt_offline_payload(b"offline secret")
            restarted_bob = E2EESession(tmp_path / "bob.key", tmp_path / "bob_trust.json", "alice")
            self.assertEqual(restarted_bob.decrypt_offline_payload(offline_frame), b"offline secret")

    def test_offline_cipher_round_trips_without_session_cipher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            alice_identity = load_or_create_identity_key(Path(tmp) / "alice_identity.key")
            bob_identity = load_or_create_identity_key(Path(tmp) / "bob_identity.key")
            bob_inbox = load_or_create_x25519_key(Path(tmp) / "bob_inbox.key")
            alice_ephemeral = generate_e2ee_key_pair()

            alice_identity_public = encode_identity_public_key(alice_identity)
            bob_identity_public = encode_identity_public_key(bob_identity)
            alice_ephemeral_public = encode_public_key(alice_ephemeral)
            bob_inbox_public = encode_public_key(bob_inbox)

            sender_cipher = create_offline_cipher_for_recipient(
                alice_ephemeral,
                bob_inbox_public,
                alice_identity_public,
                bob_identity_public,
            )
            recipient_cipher = create_offline_cipher_for_recipient_private_key(
                bob_inbox,
                alice_ephemeral_public,
                alice_identity_public,
                bob_identity_public,
            )
            token = sender_cipher.encrypt(b"offline")
            self.assertEqual(recipient_cipher.decrypt(token), b"offline")

    def test_socket_transport_frame_round_trip(self) -> None:
        left, right = socket.socketpair()
        try:
            sender = SocketTransport(left, name="test")
            receiver = SocketTransport(right, name="test")
            sender.send_frame(b"transport payload")
            self.assertEqual(receiver.recv_frame(), b"transport payload")
            self.assertEqual(sender.info.name, "test")
        finally:
            left.close()
            right.close()

    def test_message_queue_tracks_pending_and_sent(self) -> None:
        queue = MessageQueue()
        first = queue.enqueue(b"first")
        second = queue.enqueue(b"second")
        queue.mark_attempted(first.message_id)
        queue.mark_sent(first.message_id)

        self.assertEqual(first.attempts, 1)
        self.assertEqual([message.message_id for message in queue.pending()], [second.message_id])
        self.assertTrue(queue.remove(second.message_id))
        self.assertEqual(queue.pending(), [])

    def test_lan_discovery_advertisement_round_trips(self) -> None:
        advertisement = build_advertisement("192.168.1.20", 65432, "e2ee")
        endpoint = parse_advertisement(advertisement)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.host, "192.168.1.20")
        self.assertEqual(endpoint.port, 65432)
        self.assertEqual(endpoint.mode, "e2ee")

    def test_lan_discovery_rejects_invalid_advertisement(self) -> None:
        self.assertIsNone(parse_advertisement(b"not-json"))
        self.assertIsNone(parse_advertisement(build_advertisement("host", 70000, "e2ee")))

    def test_offline_store_persists_deduplicates_and_removes_packets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = OfflinePacketStore(Path(tmp) / "packets.jsonl")
            first = store.add(b"encrypted packet", ttl_seconds=60, packet_id="packet-1")
            second = store.add(b"updated encrypted packet", ttl_seconds=60, packet_id="packet-1")

            packets = store.load_all()
            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0].packet_id, first.packet_id)
            self.assertEqual(packets[0].packet_id, second.packet_id)
            self.assertEqual(packets[0].payload, b"updated encrypted packet")
            self.assertTrue(store.remove("packet-1"))
            self.assertEqual(store.load_all(), [])

    def test_offline_store_filters_by_recipient(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = OfflinePacketStore(Path(tmp) / "packets.jsonl")
            store.add(b"alice packet", ttl_seconds=60, packet_id="a", recipient="alice")
            store.add(b"bob packet", ttl_seconds=60, packet_id="b", recipient="bob")
            packets = store.load_for_recipient("alice")
            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0].payload, b"alice packet")
            self.assertTrue(store.remove("a", recipient="alice"))
            self.assertEqual(store.load_for_recipient("alice"), [])

    def test_offline_store_prunes_expired_packets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = OfflinePacketStore(Path(tmp) / "packets.jsonl")
            store.add(b"expired", ttl_seconds=-1, packet_id="old")
            store.add(b"live", ttl_seconds=60, packet_id="new")
            self.assertEqual(store.prune_expired(), 1)
            self.assertEqual([packet.packet_id for packet in store.load_all()], ["new"])

    def test_padding_round_trips_and_uses_bucket(self) -> None:
        padded = pad_payload(b"hello", buckets=(16, 32))
        self.assertEqual(len(padded), 16)
        self.assertEqual(unpad_payload(padded), b"hello")

    def test_contact_book_tracks_multiple_devices(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            book = ContactBook(Path(tmp) / "contacts.json")
            book.trust_device("alice", "phone", "fp-phone", label="Alice phone")
            book.trust_device("alice", "laptop", "fp-laptop", label="Alice laptop")

            reloaded = ContactBook(Path(tmp) / "contacts.json")
            self.assertTrue(reloaded.is_trusted("alice", "fp-phone"))
            self.assertTrue(reloaded.is_trusted("alice", "fp-laptop"))
            self.assertEqual(reloaded.trusted_fingerprints("alice"), {"fp-phone", "fp-laptop"})
            self.assertTrue(reloaded.untrust_device("alice", "phone"))
            self.assertFalse(reloaded.is_trusted("alice", "fp-phone"))
            self.assertTrue(reloaded.is_trusted("alice", "fp-laptop"))

    def test_direct_peer_listener_receives_frame(self) -> None:
        received: list[bytes] = []
        ready = threading.Event()

        def on_peer(transport) -> None:
            received.append(transport.recv_frame())
            transport.close()
            ready.set()

        listener = DirectPeerListener("127.0.0.1", 0, on_peer)
        endpoint = listener.start()
        try:
            client = connect_direct_peer(endpoint.host, endpoint.port, timeout=2)
            client.send_frame(b"direct payload")
            client.close()
            self.assertTrue(ready.wait(timeout=2))
            self.assertEqual(received, [b"direct payload"])
        finally:
            listener.stop()


if __name__ == "__main__":
    unittest.main()
