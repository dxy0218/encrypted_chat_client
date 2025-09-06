"""Encrypted chat server with latency replies and file broadcast support."""

import socket
import struct
import threading
from pathlib import Path

from cryptography.fernet import Fernet


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


def handle_client(conn: socket.socket, addr, cipher: Fernet, clients: list):
    try:
        while True:
            data = recv_encrypted(conn, cipher)
            text = data.decode(errors="ignore")
            if text.startswith("PING|"):
                send_encrypted(conn, cipher, f"PONG|{text.split('|',1)[1]}".encode())
                continue

            # Broadcast to others
            for client in list(clients):
                if client is not conn:
                    try:
                        send_encrypted(client, cipher, data)
                    except Exception:
                        clients.remove(client)
    except Exception:
        pass
    finally:
        clients.remove(conn)
        conn.close()
        print(f"Disconnected {addr}")


def main() -> None:
    key_path = Path("key.key")
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    cipher = Fernet(key_path.read_bytes())

    host = "127.0.0.1"
    port = 65432
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server started on {host}:{port}")

    clients: list[socket.socket] = []
    try:
        while True:
            conn, addr = server_socket.accept()
            clients.append(conn)
            print(f"Connected by {addr}")
            threading.Thread(target=handle_client, args=(conn, addr, cipher, clients), daemon=True).start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()

