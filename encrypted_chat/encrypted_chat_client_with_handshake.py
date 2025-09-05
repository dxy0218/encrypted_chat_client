import socket
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat

def generate_dh_key_pair():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
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

def main():
    # 生成 Diffie-Hellman 密钥对
    private_key, public_key = generate_dh_key_pair()

    # 客户端设置
    HOST = "127.0.0.1"  # 服务器地址
    PORT = 65432         # 服务器端口号

    # 创建套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")

    # 执行一次性密钥握手
    session_cipher = perform_key_exchange(client_socket, private_key, public_key)
    print("Session key established.")

    # 加载本地密钥
    local_key = load_key()
    local_cipher = Fernet(local_key)

    try:
        while True:
            message = input("Enter message: ")
            if message.lower() == "exit":
                break

            # 本地加密
            locally_encrypted_message = local_cipher.encrypt(message.encode())

            # 使用会话密钥加密
            session_encrypted_message = session_cipher.encrypt(locally_encrypted_message)

            # 发送加密消息
            client_socket.send(session_encrypted_message)

            # 接收加密消息
            encrypted_response = client_socket.recv(1024)

            # 使用会话密钥解密
            locally_encrypted_response = session_cipher.decrypt(encrypted_response)

            # 本地解密
            decrypted_response = local_cipher.decrypt(locally_encrypted_response).decode()
            print(f"Received: {decrypted_response}")

    except KeyboardInterrupt:
        print("Disconnected from server.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
