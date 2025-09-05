import os
import socket
import base64
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


def generate_dh_key_pair():
    private_key = _DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def perform_key_exchange(conn):
    client_public_bytes = conn.recv(1024)
    client_public_key = load_der_public_key(client_public_bytes)

    private_key, public_key = generate_dh_key_pair()
    conn.send(
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

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"Server started on {HOST}:{PORT}")

clients = []  # list of {'conn': conn, 'session': Fernet, 'name': str}


def broadcast(plaintext, sender_conn):
    locally_encrypted = cipher.encrypt(plaintext.encode())
    for info in clients:
        if info["conn"] is not sender_conn:
            session_encrypted = info["session"].encrypt(locally_encrypted)
            info["conn"].send(session_encrypted)


def handle_client(conn):
    session_cipher = perform_key_exchange(conn)
    client_info = {"conn": conn, "session": session_cipher, "name": None}
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
                    broadcast(message, conn)
                elif action == "LEAVE" and len(parts) == 3:
                    print(f"{parts[2]} left")
                    broadcast(message, conn)
                    left_announced = True
                    break
                elif action == "NICK" and len(parts) == 3:
                    old = client_info.get("name", "Someone")
                    client_info["name"] = parts[2]
                    broadcast(f"SYS|NICK|{old}|{parts[2]}", conn)
                    print(f"{old} is now known as {parts[2]}")
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

            broadcast(message, conn)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        clients.remove(client_info)
        if client_info.get("name") and not left_announced:
            broadcast(f"SYS|LEAVE|{client_info['name']}", conn)
            print(f"{client_info['name']} disconnected")
        conn.close()


try:
    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        Thread(target=handle_client, args=(conn,)).start()
except KeyboardInterrupt:
    print("Server shutting down...")
finally:
    server_socket.close()
