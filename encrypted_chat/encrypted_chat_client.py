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
import socket
import struct
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet
from colorama import Fore, Style, init


BUFFER_SIZE = 4096


def load_key() -> bytes:
    """Load or create the symmetric encryption key."""
    key_path = Path("key.key")
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    return key_path.read_bytes()


def send_encrypted(sock: socket.socket, cipher: Fernet, data: bytes) -> None:
    encrypted = cipher.encrypt(data)
    sock.sendall(struct.pack("!I", len(encrypted)))
    sock.sendall(encrypted)


def recv_encrypted(sock: socket.socket, cipher: Fernet) -> bytes:
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("connection closed")
    (size,) = struct.unpack("!I", header)
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return cipher.decrypt(data)


def send_text(sock: socket.socket, cipher: Fernet, text: str) -> None:
    send_encrypted(sock, cipher, text.encode())


def send_file(sock: socket.socket, cipher: Fernet, path: Path) -> None:
    filesize = path.stat().st_size
    send_text(sock, cipher, f"FILE|{path.name}|{filesize}")
    sent = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            send_encrypted(sock, cipher, chunk)
            sent += len(chunk)
            progress = sent / filesize * 100
            print(f"Sending {path.name}: {progress:.1f}%", end="\r")
    print(f"Sending {path.name}: 100%        ")


def handle_receive(
    sock: socket.socket,
    cipher: Fernet,
    stop_event: threading.Event,
    pending_reads: set[int],
    received_messages: dict[int, str],
) -> None:
    pending_file: dict[str, tuple[Path, int, int]] | None = None
    while not stop_event.is_set():
        try:
            data = recv_encrypted(sock, cipher)
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
            received_messages[msg_id] = content
            print(Fore.CYAN + f"Peer({msg_id_str}): {content}")
            send_text(sock, cipher, f"READ|{msg_id_str}")
        else:
            print(Fore.CYAN + f"{text}")


def ping_loop(sock: socket.socket, cipher: Fernet, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        ts = str(time.time())
        send_text(sock, cipher, f"PING|{ts}")
        stop_event.wait(5)


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted chat client")
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=65432, help="server port")
    args = parser.parse_args()

    key = load_key()
    cipher = Fernet(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print(f"Connected to server {args.host}:{args.port}")

    init(autoreset=True)

    stop_event = threading.Event()
    pending_reads: set[int] = set()
    received_messages: dict[int, str] = {}
    threading.Thread(
        target=handle_receive,
        args=(sock, cipher, stop_event, pending_reads, received_messages),
        daemon=True,
    ).start()
    threading.Thread(target=ping_loop, args=(sock, cipher, stop_event), daemon=True).start()

    msg_id = 0
    sent_messages: dict[int, str] = {}
    try:
        while not stop_event.is_set():
            message = input(Fore.GREEN + "Enter message (/file <path>, /exit): " + Style.RESET_ALL)
            if message.startswith("/file "):
                path = Path(message.split(" ", 1)[1]).expanduser()
                if path.exists():
                    send_file(sock, cipher, path)
                else:
                    print(Fore.RED + "File not found.")
            elif message.strip() == "/exit":
                break
            elif message.startswith("/recall "):
                try:
                    rid = int(message.split(" ", 1)[1])
                except ValueError:
                    print(Fore.RED + "Invalid message ID.")
                    continue
                if rid in sent_messages:
                    send_text(sock, cipher, f"RECALL|{rid}")
                    sent_messages.pop(rid, None)
                    pending_reads.discard(rid)
                    print(Fore.GREEN + f"You recalled message {rid}")
                else:
                    print(Fore.RED + "Unknown message ID.")
            else:
                msg_id += 1
                pending_reads.add(msg_id)
                sent_messages[msg_id] = message
                send_text(sock, cipher, f"MSG|{msg_id}|{message}")
                print(Fore.GREEN + f"You({msg_id}): {message} " + Style.DIM + "[sent]")
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sock.close()


if __name__ == "__main__":
    main()

