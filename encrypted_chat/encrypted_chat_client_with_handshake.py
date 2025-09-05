import socket
import base64
import argparse
import getpass
import os
import threading
import json
import uuid
import urllib.request
import time

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
CONTACTS_FILE = "contacts.json"
PROFILE_FILE = "profile.json"
EMOJI_FILE = "emojis.json"
ARCHIVE_FILE = "archive.enc"
FAVORITES_FILE = "favorites.enc"


# Basic ANSI colors for a friendlier CLI.
COLOR_INFO = "\033[96m"  # Cyan
COLOR_WARN = "\033[93m"  # Yellow
COLOR_ERROR = "\033[91m"  # Red
COLOR_INPUT = "\033[92m"  # Green
COLOR_RESET = "\033[0m"


def print_banner():
    """Display a simple startup banner and command hint."""
    print(f"{COLOR_INFO}=== Encrypted Chat Client ==={COLOR_RESET}")
    print(
        "Commands: /image <path>, /video <path>, /file <path>, /emoji <alias>,"
        " /emoji add <alias> <path>, /temp <sec> <msg>, /fav <id>, /archive <id>,"
        " /export <file>, /import <file>, /nick <name>, /exit"
    )


def require_app_password():
    for _ in range(3):
        if getpass.getpass("Enter application password: ") == APP_PASSWORD:
            return True
        print(f"{COLOR_ERROR}Incorrect password.{COLOR_RESET}")
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

def load_or_create_key():
    """Load the persistent Fernet key or create it if missing."""
    if os.path.exists("key.key"):
        with open("key.key", "rb") as key_file:
            return key_file.read()
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    return key


def get_ip_info():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    try:
        public_ip = urllib.request.urlopen("https://api.ipify.org").read().decode()
    except Exception:
        public_ip = local_ip
    return local_ip, public_ip


def load_or_create_profile(port):
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                user_id = data.get("user_id")
                name = data.get("name")
                if not name:
                    name = input("Enter display name: ").strip() or "Anonymous"
                    data["name"] = name
                    with open(PROFILE_FILE, "w", encoding="utf-8") as fw:
                        json.dump(data, fw)
                return user_id, name
            except Exception:
                pass
    local_ip, public_ip = get_ip_info()
    profile = {
        "local_ip": local_ip,
        "public_ip": public_ip,
        "port": port,
        "uuid": str(uuid.uuid4()),
    }
    user_id = base64.urlsafe_b64encode(json.dumps(profile).encode()).decode()
    name = input("Enter display name: ").strip() or "Anonymous"
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump({"user_id": user_id, "name": name}, f)
    print(f"Your user identifier: {user_id}")
    return user_id, name


def decode_identifier(token):
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        return json.loads(decoded)
    except Exception:
        return None


def next_id(state):
    msg_id = state["counter"]
    state["counter"] += 1
    return msg_id


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


def receive_messages(sock, session_cipher, local_cipher, history, state, expire_cb):
    """Continuously receive and process messages from the server."""
    ongoing = {}
    try:
        while True:
            encrypted = sock.recv(65536)
            if not encrypted:
                break
            locally_encrypted = session_cipher.decrypt(encrypted)
            message = local_cipher.decrypt(locally_encrypted).decode()
            if message.startswith("SYS|"):
                parts = message.split("|", 3)
                action = parts[1]
                if action == "JOIN" and len(parts) == 3:
                    print(f"{COLOR_WARN}* {parts[2]} joined the chat *{COLOR_RESET}")
                elif action == "LEAVE" and len(parts) == 3:
                    print(f"{COLOR_WARN}* {parts[2]} left the chat *{COLOR_RESET}")
                elif action == "NICK" and len(parts) == 4:
                    print(
                        f"{COLOR_WARN}* {parts[2]} is now known as {parts[3]} *{COLOR_RESET}"
                    )
                continue

            msg_id = next_id(state)

            if message.startswith("IMG|"):
                _, filename, b64_data = message.split("|", 2)
                image_bytes = base64.b64decode(b64_data)
                save_name = f"received_{filename}"
                with open(save_name, "wb") as img_out:
                    img_out.write(image_bytes)
                print(
                    f"{COLOR_INFO}[Peer #{msg_id}] Image saved as {save_name}{COLOR_RESET}"
                )
                history.append({"id": msg_id, "dir": "in", "type": "image", "name": filename, "time": time.time()})
            elif message.startswith("VIDSTART|"):
                _, filename, size = message.split("|", 2)
                save_name = f"received_{filename}"
                ongoing[filename] = open(save_name, "wb")
                print(
                    f"{COLOR_INFO}Receiving video: {filename} ({size} bytes){COLOR_RESET}"
                )
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
                    print(
                        f"{COLOR_INFO}[Peer #{msg_id}] Video saved as received_{filename}{COLOR_RESET}"
                    )
                    history.append({"id": msg_id, "dir": "in", "type": "video", "name": filename, "time": time.time()})
            elif message.startswith("FILESTART|"):
                _, filename, size = message.split("|", 2)
                save_name = f"received_{filename}"
                ongoing[filename] = open(save_name, "wb")
                print(
                    f"{COLOR_INFO}Receiving file: {filename} ({size} bytes){COLOR_RESET}"
                )
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
                    print(
                        f"{COLOR_INFO}[Peer #{msg_id}] File saved as received_{filename}{COLOR_RESET}"
                    )
                    history.append({"id": msg_id, "dir": "in", "type": "file", "name": filename, "time": time.time()})
            elif message.startswith("TEMP|"):
                _, ttl, text = message.split("|", 2)
                print(f"{COLOR_INFO}[Peer #{msg_id}] {text} (expires in {ttl}s){COLOR_RESET}")
                expires = time.time() + int(ttl)
                history.append({"id": msg_id, "dir": "in", "text": text, "time": time.time(), "expires": expires})
                threading.Timer(int(ttl), lambda: expire_cb(msg_id)).start()
            else:
                print(f"{COLOR_INFO}[Peer #{msg_id}] {message}{COLOR_RESET}")
                history.append({"id": msg_id, "dir": "in", "text": message, "time": time.time()})
    except Exception as e:
        print(f"{COLOR_ERROR}Receive error: {e}{COLOR_RESET}")

def start_chat(host, port, name):
    private_key, public_key = generate_dh_key_pair()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"{COLOR_INFO}Connected to server {host}:{port}{COLOR_RESET}")

    session_cipher = perform_key_exchange(client_socket, private_key, public_key)
    print(f"{COLOR_INFO}Session key established.{COLOR_RESET}")
    print_banner()

    local_key = load_or_create_key()
    local_cipher = Fernet(local_key)

    send_encrypted(client_socket, f"SYS|JOIN|{name}", session_cipher, local_cipher)

    history = []
    state = {"counter": 1}

    def expire_message(msg_id):
        print(f"{COLOR_WARN}Message {msg_id} expired.{COLOR_RESET}")
        for m in history:
            if m["id"] == msg_id:
                m["expired"] = True
                break

    emojis = load_emojis()

    receiver = threading.Thread(
        target=receive_messages,
        args=(client_socket, session_cipher, local_cipher, history, state, expire_message),
        daemon=True,
    )
    receiver.start()

    try:
        while True:
            message = input(f"{COLOR_INPUT}> {COLOR_RESET}").strip()
            if message == "/exit":
                break

            if message.startswith("/emoji"):
                parts = message.split()
                if len(parts) == 1 or parts[1] == "list":
                    if emojis:
                        for alias in emojis:
                            print(f"  {alias} -> {emojis[alias]}")
                    else:
                        print("  (no emojis)")
                elif parts[1] == "add" and len(parts) == 4:
                    alias, path = parts[2], parts[3]
                    if os.path.exists(path):
                        emojis[alias] = path
                        save_emojis(emojis)
                        print(f"{COLOR_INFO}Emoji {alias} added.{COLOR_RESET}")
                    else:
                        print(f"{COLOR_ERROR}File not found: {path}{COLOR_RESET}")
                elif len(parts) == 2:
                    alias = parts[1]
                    path = emojis.get(alias)
                    if path and os.path.exists(path):
                        try:
                            with open(path, "rb") as img_file:
                                img_data = img_file.read()
                        except OSError:
                            print(f"{COLOR_ERROR}Cannot read image: {path}{COLOR_RESET}")
                            continue
                        b64_data = base64.b64encode(img_data).decode()
                        payload = f"IMG|{os.path.basename(path)}|{b64_data}"
                        send_encrypted(client_socket, payload, session_cipher, local_cipher)
                        msg_id = next_id(state)
                        history.append(
                            {
                                "id": msg_id,
                                "dir": "out",
                                "type": "image",
                                "name": os.path.basename(path),
                                "time": time.time(),
                            }
                        )
                    else:
                        print(f"{COLOR_WARN}Unknown emoji: {alias}{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}Usage: /emoji <alias>|add <alias> <path>|list{COLOR_RESET}")
            elif message.startswith("/temp "):
                parts = message.split(" ", 2)
                if len(parts) < 3:
                    print(f"{COLOR_WARN}Usage: /temp <seconds> <message>{COLOR_RESET}")
                    continue
                try:
                    ttl = int(parts[1])
                except ValueError:
                    print(f"{COLOR_ERROR}Invalid seconds.{COLOR_RESET}")
                    continue
                text = parts[2]
                send_encrypted(client_socket, f"TEMP|{ttl}|{text}", session_cipher, local_cipher)
                msg_id = next_id(state)
                expires = time.time() + ttl
                history.append({"id": msg_id, "dir": "out", "text": text, "time": time.time(), "expires": expires})
                print(f"{COLOR_INFO}[You #{msg_id}] {text} (expires in {ttl}s){COLOR_RESET}")
                threading.Timer(ttl, lambda: expire_message(msg_id)).start()
            elif message.startswith("/fav "):
                try:
                    msg_id = int(message.split(" ", 1)[1])
                except ValueError:
                    print(f"{COLOR_ERROR}Invalid message id.{COLOR_RESET}")
                    continue
                entry = next((m for m in history if m["id"] == msg_id and not m.get("expired")), None)
                if entry:
                    favs = load_encrypted_list(FAVORITES_FILE, local_cipher)
                    favs.append(entry)
                    save_encrypted_list(FAVORITES_FILE, favs, local_cipher)
                    print(f"{COLOR_INFO}Message {msg_id} favorited.{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}Message not found.{COLOR_RESET}")
            elif message.startswith("/archive "):
                try:
                    msg_id = int(message.split(" ", 1)[1])
                except ValueError:
                    print(f"{COLOR_ERROR}Invalid message id.{COLOR_RESET}")
                    continue
                entry = next((m for m in history if m["id"] == msg_id and not m.get("expired")), None)
                if entry:
                    arch = load_encrypted_list(ARCHIVE_FILE, local_cipher)
                    arch.append(entry)
                    save_encrypted_list(ARCHIVE_FILE, arch, local_cipher)
                    print(f"{COLOR_INFO}Message {msg_id} archived.{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}Message not found.{COLOR_RESET}")
            elif message.startswith("/export "):
                filename = message.split(" ", 1)[1]
                data = [m for m in history if not m.get("expired")]
                with open(filename, "wb") as f:
                    f.write(local_cipher.encrypt(json.dumps(data).encode()))
                print(f"{COLOR_INFO}History exported to {filename}{COLOR_RESET}")
            elif message.startswith("/import "):
                filename = message.split(" ", 1)[1]
                if not os.path.exists(filename):
                    print(f"{COLOR_ERROR}File not found.{COLOR_RESET}")
                    continue
                try:
                    with open(filename, "rb") as f:
                        data = json.loads(local_cipher.decrypt(f.read()).decode())
                    history.extend(data)
                    if data:
                        state["counter"] = max(state["counter"], max(m["id"] for m in history) + 1)
                    print(f"{COLOR_INFO}Imported {len(data)} messages.{COLOR_RESET}")
                except Exception:
                    print(f"{COLOR_ERROR}Import failed.{COLOR_RESET}")
            elif message.startswith("/nick "):
                new_name = message.split(" ", 1)[1].strip()
                if new_name:
                    send_encrypted(client_socket, f"SYS|NICK|{new_name}", session_cipher, local_cipher)
                    print(f"{COLOR_INFO}Nickname changed to {new_name}{COLOR_RESET}")
                    name = new_name
                else:
                    print(f"{COLOR_ERROR}Invalid nickname.{COLOR_RESET}")
            elif message.startswith("/image "):
                path = message.split(" ", 1)[1]
                try:
                    with open(path, "rb") as img_file:
                        img_data = img_file.read()
                except OSError:
                    print(f"{COLOR_ERROR}Cannot read image: {path}{COLOR_RESET}")
                    continue
                b64_data = base64.b64encode(img_data).decode()
                payload = f"IMG|{os.path.basename(path)}|{b64_data}"
                send_encrypted(client_socket, payload, session_cipher, local_cipher)
                msg_id = next_id(state)
                history.append(
                    {
                        "id": msg_id,
                        "dir": "out",
                        "type": "image",
                        "name": os.path.basename(path),
                        "time": time.time(),
                    }
                )
                print(f"{COLOR_INFO}[You #{msg_id}] sent image {os.path.basename(path)}{COLOR_RESET}")
            elif message.startswith("/video "):
                path = message.split(" ", 1)[1]
                if not os.path.exists(path):
                    print(f"{COLOR_ERROR}Cannot read video: {path}{COLOR_RESET}")
                    continue
                send_large_file(client_socket, path, "VID", session_cipher, local_cipher)
                msg_id = next_id(state)
                history.append(
                    {
                        "id": msg_id,
                        "dir": "out",
                        "type": "video",
                        "name": os.path.basename(path),
                        "time": time.time(),
                    }
                )
                print(f"{COLOR_INFO}[You #{msg_id}] sent video {os.path.basename(path)}{COLOR_RESET}")
            elif message.startswith("/file "):
                path = message.split(" ", 1)[1]
                if not os.path.exists(path):
                    print(f"{COLOR_ERROR}Cannot read file: {path}{COLOR_RESET}")
                    continue
                send_large_file(client_socket, path, "FILE", session_cipher, local_cipher)
                msg_id = next_id(state)
                history.append(
                    {
                        "id": msg_id,
                        "dir": "out",
                        "type": "file",
                        "name": os.path.basename(path),
                        "time": time.time(),
                    }
                )
                print(f"{COLOR_INFO}[You #{msg_id}] sent file {os.path.basename(path)}{COLOR_RESET}")
            else:
                send_encrypted(client_socket, message, session_cipher, local_cipher)
                msg_id = next_id(state)
                history.append({"id": msg_id, "dir": "out", "text": message, "time": time.time()})
                print(f"{COLOR_INFO}[You #{msg_id}] {message}{COLOR_RESET}")
    except KeyboardInterrupt:
        print(f"{COLOR_WARN}Disconnected from server.{COLOR_RESET}")
    finally:
        try:
            send_encrypted(client_socket, f"SYS|LEAVE|{name}", session_cipher, local_cipher)
        except Exception:
            pass
        client_socket.close()


def load_contacts():
    if os.path.exists(CONTACTS_FILE):
        with open(CONTACTS_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_contacts(contacts):
    with open(CONTACTS_FILE, "w", encoding="utf-8") as f:
        json.dump(contacts, f)


def load_emojis():
    if os.path.exists(EMOJI_FILE):
        with open(EMOJI_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_emojis(emojis):
    with open(EMOJI_FILE, "w", encoding="utf-8") as f:
        json.dump(emojis, f)


def load_encrypted_list(filename, cipher):
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            try:
                data = cipher.decrypt(f.read()).decode()
                return json.loads(data)
            except Exception:
                return []
    return []


def save_encrypted_list(filename, entries, cipher):
    with open(filename, "wb") as f:
        encrypted = cipher.encrypt(json.dumps(entries).encode())
        f.write(encrypted)


def contacts_mode(default_port, self_name):
    contacts = load_contacts()
    while True:
        print(f"\n{COLOR_INFO}Contacts:{COLOR_RESET}")
        visible = {k: v for k, v in contacts.items() if not v.get("hidden")}
        if visible:
            for alias, addr in visible.items():
                print(f"  - {alias}: {addr['host']}:{addr['port']}")
        else:
            print("  (no contacts)")
        choice = input(
            f"{COLOR_INPUT}Select contact or command [add/remove/hide/unhide/exit]: {COLOR_RESET}"
        ).strip()
        if choice == "add":
            alias = input(f"{COLOR_INPUT}Name: {COLOR_RESET}")
            token_or_ip = input(
                f"{COLOR_INPUT}Identifier or IP address: {COLOR_RESET}"
            ).strip()
            port_in = input(
                f"{COLOR_INPUT}Port (default {default_port}): {COLOR_RESET}"
            ).strip()
            port = int(port_in) if port_in else default_port
            data = decode_identifier(token_or_ip)
            if data:
                host = data.get("public_ip") or data.get("local_ip")
                port = data.get("port", port)
                contacts[alias] = {"host": host, "port": port, "id": token_or_ip}
            else:
                contacts[alias] = {"host": token_or_ip, "port": port}
            save_contacts(contacts)
            print(f"{COLOR_INFO}Contact {alias} added.{COLOR_RESET}")
        elif choice == "remove":
            alias = input(f"{COLOR_INPUT}Name to remove: {COLOR_RESET}")
            if alias in contacts:
                contacts.pop(alias)
                save_contacts(contacts)
                print(f"{COLOR_INFO}Contact {alias} removed.{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}Contact not found.{COLOR_RESET}")
        elif choice == "hide":
            alias = input(f"{COLOR_INPUT}Name to hide: {COLOR_RESET}")
            if alias in contacts:
                contacts[alias]["hidden"] = True
                save_contacts(contacts)
                print(f"{COLOR_INFO}Contact {alias} hidden.{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}Contact not found.{COLOR_RESET}")
        elif choice == "unhide":
            alias = input(f"{COLOR_INPUT}Name to unhide: {COLOR_RESET}")
            if alias in contacts:
                contacts[alias]["hidden"] = False
                save_contacts(contacts)
                print(f"{COLOR_INFO}Contact {alias} unhidden.{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}Contact not found.{COLOR_RESET}")
        elif choice == "exit":
            break
        elif choice in contacts:
            info = contacts[choice]
            start_chat(info['host'], info['port'], self_name)
        else:
            print(f"{COLOR_WARN}Unknown option.{COLOR_RESET}")


def main():
    parser = argparse.ArgumentParser(description="Encrypted chat client")
    parser.add_argument("host", nargs="?", help="Server IP for direct mode")
    parser.add_argument("--port", type=int, default=65432, help="Server port")
    parser.add_argument("--mode", choices=["direct", "contacts"], help="Chat mode")
    args = parser.parse_args()

    if not require_app_password():
        print(f"{COLOR_ERROR}Authentication failed.{COLOR_RESET}")
        return

    user_id, name = load_or_create_profile(args.port)
    print(f"{COLOR_INFO}Your identifier: {user_id}{COLOR_RESET}")

    mode = args.mode
    if not mode:
        mode = (
            input(
                f"{COLOR_INPUT}Select mode: 'direct' for IP chat or 'contacts': {COLOR_RESET}"
            )
            .strip()
            .lower()
        )

    if mode == "direct":
        target = args.host or input(
            f"{COLOR_INPUT}Enter target IP or identifier: {COLOR_RESET}"
        ).strip()
        data = decode_identifier(target)
        if data:
            host = data.get("public_ip") or data.get("local_ip")
            port = data.get("port", args.port)
        else:
            host, port = target, args.port
        start_chat(host, port, name)
    elif mode == "contacts":
        contacts_mode(args.port, name)
    else:
        print(f"{COLOR_ERROR}Unknown mode.{COLOR_RESET}")

if __name__ == "__main__":
    main()

