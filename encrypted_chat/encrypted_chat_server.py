"""Encrypted chat server with latency replies and file broadcast support."""

from __future__ import annotations

import argparse
import socket
import threading
from pathlib import Path

try:
    from .lan_discovery import DEFAULT_DISCOVERY_PORT, start_lan_advertiser
    from .messages import ack_packet, parse_store_packet, stored_packet
    from .offline_store import OfflinePacketStore
    from .protocol import DEFAULT_KEY_FILE, Cipher, create_cipher, recv_encrypted, recv_frame, send_encrypted, send_frame
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from lan_discovery import DEFAULT_DISCOVERY_PORT, start_lan_advertiser
    from messages import ack_packet, parse_store_packet, stored_packet
    from offline_store import OfflinePacketStore
    from protocol import DEFAULT_KEY_FILE, Cipher, create_cipher, recv_encrypted, recv_frame, send_encrypted, send_frame


def remove_client(conn: socket.socket, clients: list[socket.socket], clients_lock: threading.Lock) -> None:
    with clients_lock:
        if conn in clients:
            clients.remove(conn)


def broadcast_frame(
    sender: socket.socket,
    data: bytes,
    clients: list[socket.socket],
    clients_lock: threading.Lock,
) -> None:
    with clients_lock:
        recipients = [client for client in clients if client is not sender]
    for client in recipients:
        try:
            send_frame(client, data)
        except Exception:
            remove_client(client, clients, clients_lock)
            client.close()


def handle_shared_client(
    conn: socket.socket,
    addr: tuple[str, int],
    cipher: Cipher,
    clients: list[socket.socket],
    clients_lock: threading.Lock,
) -> None:
    try:
        while True:
            data = recv_encrypted(conn, cipher)
            text = data.decode(errors="ignore")
            if text.startswith("PING|"):
                send_encrypted(conn, cipher, f"PONG|{text.split('|',1)[1]}".encode())
                continue

            with clients_lock:
                recipients = [client for client in clients if client is not conn]
            for client in recipients:
                try:
                    send_encrypted(client, cipher, data)
                except Exception:
                    remove_client(client, clients, clients_lock)
                    client.close()
    except Exception as exc:
        print(f"Client {addr} disconnected: {exc}")
    finally:
        remove_client(conn, clients, clients_lock)
        conn.close()
        print(f"Disconnected {addr}")


def handle_e2ee_client(
    conn: socket.socket,
    addr: tuple[str, int],
    clients: list[socket.socket],
    clients_lock: threading.Lock,
    offline_store: OfflinePacketStore | None = None,
) -> None:
    try:
        while True:
            data = recv_frame(conn)
            text = data.decode(errors="ignore")
            if text.startswith("PING|"):
                send_frame(conn, f"PONG|{text.split('|', 1)[1]}".encode())
                continue
            if text.startswith("STORE|") and offline_store is not None:
                recipient, ttl_seconds, packet_id, payload = parse_store_packet(text)
                offline_store.add(payload, ttl_seconds=ttl_seconds, packet_id=packet_id, recipient=recipient)
                send_frame(conn, ack_packet(packet_id).encode())
                continue
            if text.startswith("FETCH|") and offline_store is not None:
                recipient = text.split("|", 1)[1]
                offline_store.prune_expired()
                for packet in offline_store.load_for_recipient(recipient):
                    send_frame(conn, stored_packet(packet.packet_id, packet.payload).encode())
                    offline_store.remove(packet.packet_id, recipient=recipient)
                continue
            broadcast_frame(conn, data, clients, clients_lock)
    except Exception as exc:
        print(f"Client {addr} disconnected: {exc}")
    finally:
        remove_client(conn, clients, clients_lock)
        conn.close()
        print(f"Disconnected {addr}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted chat relay server")
    parser.add_argument(
        "--mode",
        choices=("e2ee", "shared"),
        default="e2ee",
        help="e2ee relays opaque client-encrypted frames; shared decrypts with server key",
    )
    parser.add_argument("--host", default="127.0.0.1", help="address to bind")
    parser.add_argument("--port", type=int, default=65432, help="port to bind")
    parser.add_argument("--lan-advertise", action="store_true", help="broadcast this relay endpoint on the LAN")
    parser.add_argument("--lan-advertise-host", help="host value to publish in LAN advertisements")
    parser.add_argument("--lan-discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT, help="UDP LAN discovery port")
    parser.add_argument(
        "--offline-store",
        type=Path,
        help="JSONL store for E2EE store-and-forward packets",
    )
    parser.add_argument(
        "--key-file",
        action="append",
        dest="key_files",
        help="shared Fernet key file; repeat for multi-layer encryption",
    )
    args = parser.parse_args()

    cipher = create_cipher(args.key_files or DEFAULT_KEY_FILE) if args.mode == "shared" else None
    offline_store = OfflinePacketStore(args.offline_store) if args.offline_store and args.mode == "e2ee" else None

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((args.host, args.port))
    server_socket.listen()
    print(f"Server started on {args.host}:{args.port} ({args.mode} mode)")

    clients: list[socket.socket] = []
    clients_lock = threading.Lock()
    advertiser_stop = threading.Event()
    if args.lan_advertise:
        advertised_host = args.lan_advertise_host or args.host
        start_lan_advertiser(
            advertised_host,
            args.port,
            args.mode,
            advertiser_stop,
            discovery_port=args.lan_discovery_port,
        )
        print(f"LAN discovery advertisement enabled for {advertised_host}:{args.port}")
    try:
        while True:
            conn, addr = server_socket.accept()
            with clients_lock:
                clients.append(conn)
            print(f"Connected by {addr}")
            if args.mode == "shared":
                threading.Thread(
                    target=handle_shared_client,
                    args=(conn, addr, cipher, clients, clients_lock),
                    daemon=True,
                ).start()
            else:
                threading.Thread(
                    target=handle_e2ee_client,
                    args=(conn, addr, clients, clients_lock, offline_store),
                    daemon=True,
                ).start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        advertiser_stop.set()
        with clients_lock:
            open_clients = list(clients)
            clients.clear()
        for client in open_clients:
            try:
                client.close()
            except OSError:
                pass
        server_socket.close()


if __name__ == "__main__":
    main()

