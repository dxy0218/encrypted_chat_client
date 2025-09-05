import socket
from cryptography.fernet import Fernet

# 生成加密密钥
key = Fernet.generate_key()
cipher = Fernet(key)

# 保存密钥到文件（仅供测试，生产环境需安全存储）
with open("key.key", "wb") as key_file:
    key_file.write(key)

# 服务器设置
HOST = "127.0.0.1"  # 本地地址
PORT = 65432         # 端口号

# 创建套接字
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()
print(f"Server started on {HOST}:{PORT}")

clients = []

def broadcast(message, sender):
    for client in clients:
        if client != sender:
            client.send(message)

try:
    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        clients.append(conn)

        # 接收消息的线程
        def handle_client(client):
            while True:
                try:
                    encrypted_message = client.recv(65536)
                    if not encrypted_message:
                        break

                    # 解密消息
                    message = cipher.decrypt(encrypted_message).decode()
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
                    else:
                        print(f"Received: {message}")

                    # 广播加密消息
                    broadcast(encrypted_message, client)
                except Exception as e:
                    print(f"Error: {e}")
                    break

            clients.remove(client)
            client.close()

        # 启动线程处理客户端
        from threading import Thread
        Thread(target=handle_client, args=(conn,)).start()

except KeyboardInterrupt:
    print("Server shutting down...")
finally:
    server_socket.close()
