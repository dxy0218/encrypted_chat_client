import socket
import base64
import argparse
import getpass
import os
import threading

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

# Predefined Diffie-Hellman parameters (2048-bit MODP Group)
# Using static parameters avoids the expensive generation step on each run.
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

APP_PASSWORD = "letmein"


def require_app_password():
    for _ in range(3):
        if getpass.getpass("Enter application password: ") == APP_PASSWORD:
            return True
        print("Incorrect password.")
    return False

def generate_dh_key_pair():
    private_key = _DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def perform_key_exchange(client_socket, private_key, public_key):
    # 发送公钥到服务器
    public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    client_socket.send(public_key_bytes)

    # 接收服务器的公钥
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = load_der_public_key(server_public_key_bytes)

    # 生成共享密钥
    shared_key = private_key.exchange(server_public_key)
    derived_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"handshake").derive(shared_key)
    return Fernet(base64.urlsafe_b64encode(derived_key))

def load_key():
    # 从文件加载加密密钥
    with open("key.key", "rb") as key_file:
        return key_file.read()


def send_encrypted(sock, payload, session_cipher, local_cipher):
    """Encrypt payload with local and session keys then send."""
    locally_encrypted = local_cipher.encrypt(payload.encode())
    session_encrypted = session_cipher.encrypt(locally_encrypted)
    sock.sendall(session_encrypted)


def send_large_file(sock, path, tag, session_cipher, local_cipher, chunk_size=32768):
    """Send large files (videos or generic files) in chunks."""
    filename = os.path.basename(path)
    size = os.path.getsize(path)
    send_encrypted(sock, f"{tag}START|{filename}|{size}", session_cipher, local_cipher)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            b64 = base64.b64encode(chunk).decode()
            send_encrypted(sock, f"{tag}CHUNK|{filename}|{b64}", session_cipher, local_cipher)
    send_encrypted(sock, f"{tag}END|{filename}", session_cipher, local_cipher)


def receive_messages(sock, session_cipher, local_cipher):
    """Continuously receive and process messages from the server."""
    ongoing = {}
    try:
        while True:
            encrypted = sock.recv(65536)
            if not encrypted:
                break
            locally_encrypted = session_cipher.decrypt(encrypted)
            message = local_cipher.decrypt(locally_encrypted).decode()

            if message.startswith("IMG|"):
                _, filename, b64_data = message.split("|", 2)
                image_bytes = base64.b64decode(b64_data)
                save_name = f"received_{filename}"
                with open(save_name, "wb") as img_out:
                    img_out.write(image_bytes)
                print(f"Received image saved as {save_name}")
            elif message.startswith("VIDSTART|"):
                _, filename, size = message.split("|", 2)
                save_name = f"received_{filename}"
                ongoing[filename] = open(save_name, "wb")
                print(f"Receiving video: {filename} ({size} bytes)")
            elif message.startswith("VIDCHUNK|"):
                _, filename, b64_data = message.split("|", 2)
                f = ongoing.get(filename)
                if f:
                    f.write(base64.b64decode(b64_data))
            elif message.startswith("VIDEND|"):
                _, filename = message.split("|", 1)
                f = ongoing.pop(filename, None)
                if f:
                    f.close()
                    print(f"Received video saved as received_{filename}")
            elif message.startswith("FILESTART|"):
                _, filename, size = message.split("|", 2)
                save_name = f"received_{filename}"
                ongoing[filename] = open(save_name, "wb")
                print(f"Receiving file: {filename} ({size} bytes)")
            elif message.startswith("FILECHUNK|"):
                _, filename, b64_data = message.split("|", 2)
                f = ongoing.get(filename)
                if f:
                    f.write(base64.b64decode(b64_data))
            elif message.startswith("FILEEND|"):
                _, filename = message.split("|", 1)
                f = ongoing.pop(filename, None)
                if f:
                    f.close()
                    print(f"Received file saved as received_{filename}")
            else:
                print(f"Received: {message}")
    except Exception as e:
        print(f"Receive error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Encrypted chat client")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Server IP address")
    parser.add_argument("--port", type=int, default=65432, help="Server port")
    args = parser.parse_args()

    if not require_app_password():
        print("Authentication failed.")
        return

    private_key, public_key = generate_dh_key_pair()

    HOST = args.host
    PORT = args.port

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")

    session_cipher = perform_key_exchange(client_socket, private_key, public_key)
    print("Session key established.")

    # 加载本地密钥
    local_key = load_key()
    local_cipher = Fernet(local_key)

    receiver = threading.Thread(
        target=receive_messages, args=(client_socket, session_cipher, local_cipher), daemon=True
    )
    receiver.start()

    try:
        while True:
            message = input("Enter message or 'image <path>'/'video <path>'/'file <path>': ")
            if message.lower() == "exit":
                break

            if message.startswith("image "):
                path = message.split(" ", 1)[1]
                with open(path, "rb") as img_file:
                    img_data = img_file.read()
                b64_data = base64.b64encode(img_data).decode()
                payload = f"IMG|{os.path.basename(path)}|{b64_data}"
                send_encrypted(client_socket, payload, session_cipher, local_cipher)
            elif message.startswith("video "):
                path = message.split(" ", 1)[1]
                send_large_file(client_socket, path, "VID", session_cipher, local_cipher)
            elif message.startswith("file "):
                path = message.split(" ", 1)[1]
                send_large_file(client_socket, path, "FILE", session_cipher, local_cipher)
            else:
                send_encrypted(client_socket, message, session_cipher, local_cipher)

    except KeyboardInterrupt:
        print("Disconnected from server.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()

