"""Encrypted chat client with file transfer, latency display and easier CLI.

This script provides a command-line client capable of:
* sending and receiving text messages with length-prefixed framing for
  smoother encode/decode handling;
* measuring round-trip latency to the server in real time;
* transferring large files with progress feedback;
* showing read receipts for sent messages; and
* allowing senders to recall previously sent messages; and
* colorized output with simple commands (``/file``, ``/recall`` and ``/exit``)
  to reduce operational difficulty.
"""

from __future__ import annotations

import argparse
import queue
import socket
import threading
import time
from pathlib import Path

from colorama import Fore, Style, init

try:
    from .direct_peer import DirectPeerListener, connect_direct_peer
    from .lan_discovery import DEFAULT_DISCOVERY_PORT, discover_lan_relay
    from .messages import (
        UNVERIFIED_LIMIT,
        fetch_packets,
        file_header,
        mark_unverified,
        msg,
        parse_stored_packet,
        read,
        recall,
        store_packet,
        strip_unverified,
    )
    from .protocol import (
        DEFAULT_KEY_FILE,
        Cipher,
        create_cipher,
        recv_encrypted,
        recv_frame,
        send_encrypted,
        send_frame,
    )
    from .session import E2EESession
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from direct_peer import DirectPeerListener, connect_direct_peer
    from lan_discovery import DEFAULT_DISCOVERY_PORT, discover_lan_relay
    from messages import (
        UNVERIFIED_LIMIT,
        fetch_packets,
        file_header,
        mark_unverified,
        msg,
        parse_stored_packet,
        read,
        recall,
        store_packet,
        strip_unverified,
    )
    from protocol import (
        DEFAULT_KEY_FILE,
        Cipher,
        create_cipher,
        recv_encrypted,
        recv_frame,
        send_encrypted,
        send_frame,
    )
    from session import E2EESession


BUFFER_SIZE = 4096


def trust_peer(e2ee_session: E2EESession) -> None:
    if e2ee_session.peer_fingerprint is None:
        print(Fore.RED + "No peer fingerprint available yet.")
        return
    if e2ee_session.safety_phrase is not None:
        print(Fore.YELLOW + f"Confirm safety phrase first: {e2ee_session.safety_phrase}")
    fingerprint = e2ee_session.trust_peer()
    print(Fore.GREEN + f"Trusted {e2ee_session.peer_alias}: {fingerprint}")


def mark_peer_rejected(e2ee_session: E2EESession, stop_event: threading.Event) -> None:
    e2ee_session.reject_peer()
    stop_event.set()
    print(Fore.RED + "Peer identity rejected. Chat disabled.")


def untrust_peer(e2ee_session: E2EESession) -> None:
    removed = e2ee_session.untrust_peer()
    if removed:
        print(Fore.YELLOW + f"Removed trusted identity for {e2ee_session.peer_alias}.")
    else:
        print(Fore.YELLOW + f"No trusted identity was stored for {e2ee_session.peer_alias}.")


def send_payload(sock: socket.socket, mode: str, cipher: Cipher | None, data: bytes) -> None:
    if mode == "shared":
        if cipher is None:
            raise RuntimeError("shared cipher is not configured")
        send_encrypted(sock, cipher, data)
    else:
        if not isinstance(cipher, E2EESession):
            raise RuntimeError("end-to-end session is not ready")
        send_frame(sock, cipher.encrypt_payload(data))


def send_text(sock: socket.socket, mode: str, cipher: Cipher | None, text: str) -> None:
    send_payload(sock, mode, cipher, text.encode())


def fetch_offline_packets(sock: socket.socket, e2ee_session: E2EESession) -> None:
    send_frame(sock, fetch_packets(e2ee_session.own_fingerprint).encode())


def print_offline_packet(packet_id: str, payload: bytes, e2ee_session: E2EESession) -> None:
    try:
        plaintext = e2ee_session.decrypt_offline_payload(payload)
    except Exception as exc:
        print(Fore.RED + f"Could not decrypt offline packet {packet_id}: {exc}")
        return
    print(Fore.CYAN + f"Offline packet {packet_id}: {plaintext.decode(errors='ignore')}")


def send_file(sock: socket.socket, mode: str, cipher: Cipher | None, path: Path) -> None:
    filesize = path.stat().st_size
    send_text(sock, mode, cipher, file_header(path.name, filesize))
    if filesize == 0:
        print(f"Sending {path.name}: 100%        ")
        return
    sent = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            send_payload(sock, mode, cipher, chunk)
            sent += len(chunk)
            progress = sent / filesize * 100
            print(f"Sending {path.name}: {progress:.1f}%", end="\r")
    print(f"Sending {path.name}: 100%        ")


def handle_receive(
    sock: socket.socket,
    mode: str,
    cipher: Cipher | None,
    e2ee_session: E2EESession | None,
    stop_event: threading.Event,
    pending_reads: set[int],
    received_messages: dict[int, str],
    offline_packets: queue.Queue[tuple[str, bytes]],
) -> None:
    pending_file: dict[str, tuple[Path, int, int]] | None = None
    while not stop_event.is_set():
        try:
            if mode == "shared":
                if cipher is None:
                    raise RuntimeError("shared cipher is not configured")
                data = recv_encrypted(sock, cipher)
            else:
                frame = recv_frame(sock)
                if frame.startswith(b"STORED|"):
                    try:
                        offline_packets.put(parse_stored_packet(frame.decode()))
                    except Exception as exc:
                        print(Fore.RED + f"Invalid offline packet from relay: {exc}")
                    continue
                if frame.startswith(b"ACK|"):
                    print(Fore.GREEN + f"Relay acknowledged {frame.decode().split('|', 1)[1]}")
                    continue
                if frame.startswith(b"PING|"):
                    send_frame(sock, f"PONG|{frame.decode().split('|', 1)[1]}".encode())
                    continue
                if frame.startswith((b"HELLO2|", b"HELLO3|")):
                    try:
                        was_ready = e2ee_session.ready.is_set() if e2ee_session is not None else False
                        peer_info = e2ee_session.process_hello(frame.decode()) if e2ee_session is not None else None
                    except Exception:
                        print(Fore.RED + "Rejected peer hello: invalid identity signature.")
                        continue
                    if peer_info is not None and e2ee_session is not None:
                        if not was_ready:
                            send_frame(sock, e2ee_session.hello.encode())
                        print(Fore.YELLOW + f"E2EE session ready. Peer identity fingerprint: {peer_info.fingerprint}")
                        print(Fore.YELLOW + f"Safety code: {peer_info.safety_code}")
                        print(Fore.YELLOW + f"Safety phrase: {peer_info.safety_phrase}")
                        if peer_info.identity_verified:
                            print(Fore.GREEN + f"Peer identity verified as {e2ee_session.peer_alias}.")
                        else:
                            print(
                                Fore.RED
                                + f"Peer identity is NOT verified. Use /trust after comparing fingerprints, or /reject."
                            )
                    continue
                if frame.startswith(b"PONG|"):
                    data = frame
                elif frame.startswith(b"E2EE|"):
                    if e2ee_session is None or e2ee_session.cipher is None:
                        print(Fore.YELLOW + "Received encrypted data before E2EE session was ready.")
                        continue
                    data = e2ee_session.decrypt_payload_frame(frame)
                else:
                    print(Fore.YELLOW + "Ignored unknown relay frame.")
                    continue
        except Exception:
            print("Connection closed by server.")
            stop_event.set()
            break

        text = data.decode(errors="ignore")
        if text.startswith("PONG|"):
            ts = float(text.split("|", 1)[1])
            latency = (time.time() - ts) * 1000
            print(Fore.MAGENTA + f"Latency: {latency:.0f} ms")
        elif text.startswith("READ|"):
            msg_id = int(text.split("|", 1)[1])
            if msg_id in pending_reads:
                pending_reads.remove(msg_id)
                print(Fore.YELLOW + f"Peer read message {msg_id}")
        elif text.startswith("FILE|"):
            _, filename, size = text.split("|", 2)
            pending_file = (Path(filename), int(size), 0)
            print(Fore.CYAN + f"Receiving {filename} ({size} bytes)")
            with pending_file[0].open("wb"):
                pass  # touch file
        elif pending_file:
            file_path, total, received = pending_file
            with file_path.open("ab") as f:
                f.write(data)
            received += len(data)
            progress = received / total * 100
            print(
                Fore.CYAN
                + f"Receiving {file_path.name}: {progress:.1f}%"
                + Style.RESET_ALL,
                end="\r",
            )
            if received >= total:
                print(Fore.CYAN + f"Receiving {file_path.name}: 100%        ")
                pending_file = None
            else:
                pending_file = (file_path, total, received)
        elif text.startswith("RECALL|"):
            msg_id = int(text.split("|", 1)[1])
            received_messages.pop(msg_id, None)
            print(Fore.CYAN + f"Peer recalled message {msg_id}")
        elif text.startswith("MSG|"):
            _, msg_id_str, content = text.split("|", 2)
            msg_id = int(msg_id_str)
            is_unverified, content = strip_unverified(content)
            verified_prefix = ""
            if is_unverified:
                verified_prefix = Fore.RED + "[unverified sender] " + Style.RESET_ALL
            received_messages[msg_id] = content
            print(Fore.CYAN + f"{verified_prefix}Peer({msg_id_str}): {content}")
            active_cipher = e2ee_session if mode == "e2ee" and e2ee_session is not None else cipher
            send_text(sock, mode, active_cipher, read(msg_id_str))
        else:
            print(Fore.CYAN + f"{text}")


def ping_loop(sock: socket.socket, mode: str, cipher: Cipher | None, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        ts = str(time.time())
        try:
            if mode == "shared":
                send_text(sock, mode, cipher, f"PING|{ts}")
            else:
                send_frame(sock, f"PING|{ts}".encode())
        except OSError:
            stop_event.set()
            break
        stop_event.wait(5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted chat client")
    parser.add_argument(
        "--mode",
        choices=("e2ee", "shared"),
        default="e2ee",
        help="e2ee encrypts between clients; shared uses the server key relay",
    )
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=65432, help="server port")
    parser.add_argument("--lan-discover", action="store_true", help="try LAN relay discovery before connecting")
    parser.add_argument("--lan-discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT, help="UDP LAN discovery port")
    parser.add_argument("--lan-discovery-timeout", type=float, default=3.0, help="LAN discovery timeout in seconds")
    parser.add_argument("--direct-connect", help="connect directly to a peer as host:port")
    parser.add_argument("--direct-listen-host", default="0.0.0.0", help="host to bind for direct peer listening")
    parser.add_argument("--direct-listen-port", type=int, default=0, help="listen for one direct peer connection")
    parser.add_argument("--peer-alias", default="default-peer", help="local name used to pin the peer fingerprint")
    parser.add_argument(
        "--identity-key",
        type=Path,
        default=Path.home() / ".encrypted_chat" / "identity_ed25519.key",
        help="persistent Ed25519 identity key file",
    )
    parser.add_argument(
        "--inbox-key",
        type=Path,
        default=None,
        help="persistent X25519 inbox key file for offline delivery",
    )
    parser.add_argument(
        "--identity-store",
        type=Path,
        default=Path.home() / ".encrypted_chat" / "trusted_peers.json",
        help="JSON file for trusted peer fingerprints",
    )
    parser.add_argument(
        "--unverified-policy",
        choices=("block", "limit"),
        default="block",
        help="block unverified E2EE chat, or allow only 5 warned messages",
    )
    parser.add_argument(
        "--pad-payloads",
        action="store_true",
        help="pad E2EE payloads before encryption; both peers must enable this",
    )
    parser.add_argument(
        "--key-file",
        action="append",
        dest="key_files",
        help="shared Fernet key file; repeat for multi-layer encryption",
    )
    args = parser.parse_args()

    cipher = create_cipher(args.key_files or DEFAULT_KEY_FILE) if args.mode == "shared" else None
    e2ee_session = (
        E2EESession(
            args.identity_key,
            args.identity_store,
            args.peer_alias,
            pad_payloads=args.pad_payloads,
            inbox_key_path=args.inbox_key,
        )
        if args.mode == "e2ee"
        else None
    )

    init(autoreset=True)
    direct_listener: DirectPeerListener | None = None
    if args.direct_connect:
        direct_host, direct_port_text = args.direct_connect.rsplit(":", 1)
        transport = connect_direct_peer(direct_host, int(direct_port_text), timeout=10)
        sock = transport.sock
        print(Fore.GREEN + f"Connected directly to peer {direct_host}:{direct_port_text}")
    elif args.direct_listen_port:
        accepted: queue.Queue[socket.socket] = queue.Queue(maxsize=1)

        def on_direct_peer(transport) -> None:
            try:
                accepted.put_nowait(transport.sock)
            except queue.Full:
                transport.close()

        direct_listener = DirectPeerListener(args.direct_listen_host, args.direct_listen_port, on_direct_peer)
        endpoint = direct_listener.start()
        print(Fore.YELLOW + f"Waiting for direct peer on {endpoint.host}:{endpoint.port}...")
        sock = accepted.get()
        print(Fore.GREEN + "Direct peer connected.")
    else:
        host = args.host
        port = args.port
        if args.lan_discover:
            endpoint = discover_lan_relay(
                timeout_seconds=args.lan_discovery_timeout,
                discovery_port=args.lan_discovery_port,
                expected_mode=args.mode,
            )
            if endpoint is not None:
                host = endpoint.host
                port = endpoint.port
                print(Fore.GREEN + f"Discovered LAN relay {host}:{port} ({endpoint.mode} mode)")
            else:
                print(Fore.YELLOW + f"No LAN relay discovered. Falling back to {host}:{port}.")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"Connected to server {host}:{port} ({args.mode} mode)")

    if args.direct_connect or args.direct_listen_port:
        if args.mode != "e2ee":
            print(Fore.YELLOW + "Direct peer transport is intended for e2ee mode.")

    if args.mode == "e2ee" and e2ee_session is not None:
        print(Fore.YELLOW + f"Your identity fingerprint: {e2ee_session.own_fingerprint}")
        send_frame(sock, e2ee_session.hello.encode())
        print(Fore.YELLOW + "Waiting for a peer to establish E2EE session...")

    stop_event = threading.Event()
    pending_reads: set[int] = set()
    received_messages: dict[int, str] = {}
    offline_packets: queue.Queue[tuple[str, bytes]] = queue.Queue()
    threading.Thread(
        target=handle_receive,
        args=(
            sock,
            args.mode,
            cipher,
            e2ee_session,
            stop_event,
            pending_reads,
            received_messages,
            offline_packets,
        ),
        daemon=True,
    ).start()
    threading.Thread(target=ping_loop, args=(sock, args.mode, cipher, stop_event), daemon=True).start()

    msg_id = 0
    sent_messages: dict[int, str] = {}
    try:
        while not stop_event.is_set():
            message = input(Fore.GREEN + "Enter message (/file <path>, /exit): " + Style.RESET_ALL)
            active_cipher = e2ee_session if args.mode == "e2ee" and e2ee_session is not None else cipher
            if args.mode == "e2ee" and message.strip() == "/trust" and e2ee_session is not None:
                trust_peer(e2ee_session)
                continue
            if args.mode == "e2ee" and message.strip() == "/fetch" and e2ee_session is not None:
                fetch_offline_packets(sock, e2ee_session)
                while True:
                    try:
                        packet_id, payload = offline_packets.get(timeout=0.5)
                    except queue.Empty:
                        break
                    print_offline_packet(packet_id, payload, e2ee_session)
                continue
            if args.mode == "e2ee" and message.strip() == "/untrust" and e2ee_session is not None:
                untrust_peer(e2ee_session)
                continue
            if args.mode == "e2ee" and message.strip() == "/reject" and e2ee_session is not None:
                mark_peer_rejected(e2ee_session, stop_event)
                break
            if args.mode == "e2ee" and e2ee_session is not None and not e2ee_session.ready.is_set():
                if message.strip() == "/exit":
                    break
                print(Fore.YELLOW + "No E2EE peer session yet. Wait for another client to connect.")
                continue
            if message.startswith("/file "):
                path = Path(message.split(" ", 1)[1]).expanduser()
                if path.exists():
                    send_file(sock, args.mode, active_cipher, path)
                else:
                    print(Fore.RED + "File not found.")
            elif message.strip() == "/exit":
                break
            elif message.startswith("/store "):
                if args.mode != "e2ee" or e2ee_session is None:
                    print(Fore.RED + "Offline store is only available in e2ee mode.")
                    continue
                if e2ee_session.peer_fingerprint is None:
                    print(Fore.RED + "No peer identity available yet.")
                    continue
                offline_text = message.split(" ", 1)[1]
                packet_id = f"offline-{int(time.time() * 1000)}"
                encrypted_packet = e2ee_session.encrypt_offline_payload(msg(packet_id, offline_text).encode())
                send_frame(
                    sock,
                    store_packet(e2ee_session.peer_fingerprint, 86400, packet_id, encrypted_packet).encode(),
                )
                print(Fore.GREEN + f"Stored offline packet {packet_id} for {e2ee_session.peer_fingerprint}.")
            elif message.startswith("/recall "):
                try:
                    rid = int(message.split(" ", 1)[1])
                except ValueError:
                    print(Fore.RED + "Invalid message ID.")
                    continue
                if rid in sent_messages:
                    send_text(sock, args.mode, active_cipher, recall(rid))
                    sent_messages.pop(rid, None)
                    pending_reads.discard(rid)
                    print(Fore.GREEN + f"You recalled message {rid}")
                else:
                    print(Fore.RED + "Unknown message ID.")
            else:
                if args.mode == "e2ee" and e2ee_session is not None and not e2ee_session.identity_verified:
                    if args.unverified_policy == "block":
                        print(
                            Fore.RED
                            + "Peer identity is not verified. Compare fingerprints and run /trust before chatting."
                        )
                        continue
                    if e2ee_session.unverified_sent >= UNVERIFIED_LIMIT:
                        print(Fore.RED + "Unverified message limit reached. Run /trust or /reject.")
                        continue
                    e2ee_session.unverified_sent += 1
                    message = mark_unverified(message)
                    print(
                        Fore.RED
                        + f"Warning: sending unverified message {e2ee_session.unverified_sent}/{UNVERIFIED_LIMIT}."
                    )
                msg_id += 1
                pending_reads.add(msg_id)
                sent_messages[msg_id] = message
                send_text(sock, args.mode, active_cipher, msg(msg_id, message))
                print(Fore.GREEN + f"You({msg_id}): {message} " + Style.DIM + "[sent]")
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sock.close()
        if direct_listener is not None:
            direct_listener.stop()


if __name__ == "__main__":
    main()

