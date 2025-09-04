import socket
from cryptography.fernet import Fernet

def load_key():
    # 从文件加载加密密钥
    with open("key.key", "rb") as key_file:
        return key_file.read()

def manage_contacts():
    contacts = {}

    while True:
        print("\nContact Management:")
        print("1. Add Contact")
        print("2. Remove Contact")
        print("3. View Contacts")
        print("4. Back to Chat")
        choice = input("Enter your choice: ")

        if choice == "1":
            name = input("Enter contact name: ")
            address = input("Enter contact address (IP:PORT): ")
            contacts[name] = address
            print(f"Contact {name} added.")
        elif choice == "2":
            name = input("Enter contact name to remove: ")
            if name in contacts:
                del contacts[name]
                print(f"Contact {name} removed.")
            else:
                print("Contact not found.")
        elif choice == "3":
            print("\nContacts:")
            for name, address in contacts.items():
                print(f"- {name}: {address}")
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please try again.")

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
            print("\nMenu:")
            print("1. Chat")
            print("2. Manage Contacts")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                while True:
                    message = input("Enter message (or type 'back' to return): ")
                    if message.lower() == "back":
                        break

                    # 加密消息
                    encrypted_message = cipher.encrypt(message.encode())

                    # 发送加密消息
                    client_socket.send(encrypted_message)

                    # 接收广播的加密消息
                    encrypted_response = client_socket.recv(1024)
                    decrypted_response = cipher.decrypt(encrypted_response).decode()
                    print(f"Received: {decrypted_response}")

            elif choice == "2":
                manage_contacts()

            elif choice == "3":
                print("Exiting chat.")
                break

            else:
                print("Invalid choice. Please try again.")

    except KeyboardInterrupt:
        print("Disconnected from server.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()