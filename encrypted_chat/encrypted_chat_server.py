import os
import socket
import base64
import time
from threading import Thread

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

_DH_P = int(
    """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
""".replace("\n", ""),
    16,
)
_DH_G = 2
_DH_PARAMETERS = dh.DHParameterNumbers(_DH_P, _DH_G).parameters()


COLOR_INFO = "\033[96m"
COLOR_RESET = "\033[0m"


def show_startup_screen():
    """Clear the terminal and display a startup splash."""
    os.system("cls" if os.name == "nt" else "clear")
    art = r"""
========================================
||                                    ||
||       隧道聊天服务器              ||
||                                    ||
========================================
"""
    print(f"{COLOR_INFO}{art}{COLOR_RESET}")
    time.sleep(1)


def generate_dh_key_pair():
    private_key = _DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def perform_key_exchange(conn):
    client_public_bytes = conn.recv(1024)
    client_public_key = load_der_public_key(client_public_bytes)

    private_key, public_key = generate_dh_key_pair()
    conn.sendall(
        public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )

    shared_key = private_key.exchange(client_public_key)
    derived = HKDF(
        algorithm=SHA256(), length=32, salt=None, info=b"handshake"
    ).derive(shared_key)
    return Fernet(base64.urlsafe_b64encode(derived))


if os.path.exists("key.key"):
    with open("key.key", "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

cipher = Fernet(key)

HOST = "127.0.0.1"
PORT = 65432

show_startup_screen()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"隧道聊天服务器启动在 {HOST}:{PORT}")

clients = []  # list of {'conn': conn, 'session': Fernet, 'name': str, 'group': str}


def broadcast(plaintext, sender_conn, group):
    locally_encrypted = cipher.encrypt(plaintext.encode())
    for info in clients:
        if info["conn"] is not sender_conn and info.get("group") == group:
            session_encrypted = info["session"].encrypt(locally_encrypted)
            info["conn"].sendall(session_encrypted)


def handle_client(conn):
    session_cipher = perform_key_exchange(conn)
    client_info = {"conn": conn, "session": session_cipher, "name": None, "group": None}
    clients.append(client_info)
    left_announced = False
    try:
        while True:
            encrypted_message = conn.recv(65536)
            if not encrypted_message:
                break

            try:
                locally_encrypted = session_cipher.decrypt(encrypted_message)
                message = cipher.decrypt(locally_encrypted).decode()
            except Exception as exc:
                print(f"Decrypt error: {exc}")
                continue

            if message.startswith("SYS|"):
                parts = message.split("|", 3)
                action = parts[1]
                if action == "JOIN" and len(parts) == 3:
                    client_info["name"] = parts[2]
                    print(f"{parts[2]} joined")
                elif action == "LEAVE" and len(parts) == 3:
                    print(f"{parts[2]} left")
                    broadcast(message, conn, client_info.get("group"))
                    left_announced = True
                    break
                elif action == "NICK" and len(parts) == 3:
                    old = client_info.get("name", "Someone")
                    client_info["name"] = parts[2]
                    broadcast(f"SYS|NICK|{old}|{parts[2]}", conn, client_info.get("group"))
                    print(f"{old} is now known as {parts[2]}")
                elif action == "GROUP" and len(parts) == 3:
                    group = parts[2]
                    old = client_info.get("group")
                    if old:
                        broadcast(f"SYS|LEAVE|{client_info.get('name', 'Someone')}", conn, old)
                    client_info["group"] = group
                    broadcast(f"SYS|JOIN|{client_info.get('name', 'Someone')}", conn, group)
                    print(f"{client_info.get('name', 'Someone')} joined group {group}")
                continue

            if message.startswith("IMG|"):
                _, filename, _ = message.split("|", 2)
                print(f"Received image: {filename}")
            elif message.startswith("VIDSTART|"):
                _, filename, _ = message.split("|", 2)
                print(f"Receiving video: {filename}")
            elif message.startswith("VIDEND|"):
                _, filename = message.split("|", 1)
                print(f"Completed video: {filename}")
            elif message.startswith("FILESTART|"):
                _, filename, _ = message.split("|", 2)
                print(f"Receiving file: {filename}")
            elif message.startswith("FILEEND|"):
                _, filename = message.split("|", 1)
                print(f"Completed file: {filename}")
            elif message.startswith("TEMP|"):
                _, ttl, _ = message.split("|", 2)
                print(f"Temporary message with TTL {ttl}s")
            else:
                print(f"Received: {message}")

            broadcast(message, conn, client_info.get("group"))
    except Exception as e:
        print(f"Error: {e}")
    finally:
        clients.remove(client_info)
        if client_info.get("name") and not left_announced:
            broadcast(f"SYS|LEAVE|{client_info['name']}", conn, client_info.get("group"))
            print(f"{client_info['name']} disconnected")
        conn.close()


try:
    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        Thread(target=handle_client, args=(conn,)).start()
except KeyboardInterrupt:
    print("隧道聊天服务器正在关闭...")
finally:
    server_socket.close()
