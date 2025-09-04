import socket
from cryptography.fernet import Fernet

def load_key():
    # 从文件加载加密密钥
    with open("key.key", "rb") as key_file:
        return key_file.read()

def main():
    key = load_key()
    cipher = Fernet(key)

    # 客户端设置
    HOST = "127.0.0.1"  # 服务器地址
    PORT = 65432         # 服务器端口号

    # 创建套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print(f"Connected to server {HOST}:{PORT}")

    try:
        while True:
            # 输入消息
            message = input("Enter message: ")
            if message.lower() == "exit":
                break

            # 加密消息
            encrypted_message = cipher.encrypt(message.encode())

            # 发送加密消息
            client_socket.send(encrypted_message)

            # 接收广播的加密消息
            encrypted_response = client_socket.recv(1024)
            decrypted_response = cipher.decrypt(encrypted_response).decode()
            print(f"Received: {decrypted_response}")

    except KeyboardInterrupt:
        print("Disconnected from server.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()