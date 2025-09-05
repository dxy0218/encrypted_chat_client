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


# Basic ANSI color themes.  The dark theme leans into a "Matrix"-style green
# on black look while the light theme opts for a friendlier blue palette.
THEMES = {
    "dark": {
        "info": "\033[92m",  # bright green
        "warn": "\033[93m",
        "error": "\033[91m",
        "input": "\033[92m",
        "reset": "\033[0m",
    },
    "light": {
        "info": "\033[94m",  # blue
        "warn": "\033[95m",
        "error": "\033[91m",
        "input": "\033[34m",
        "reset": "\033[0m",
    },
}

COLOR_INFO = COLOR_WARN = COLOR_ERROR = COLOR_INPUT = COLOR_RESET = ""
CURRENT_THEME = "dark"

# Language dictionaries for UI strings
LANGUAGES = {
    "en": {
        "startup_art": (
            "===================================\n"
            "||                               ||\n"
            "||         Tunnel Chat           ||\n"
            "||                               ||\n"
            "==================================="
        ),
        "press_enter": "Press Enter to continue...",
        "banner_title": "=== Tunnel Chat ===",
        "command_hint": (
            "Commands: /image <path>, /video <path>, /file <path>, /emoji <alias>,"
            " /emoji add <alias> <path>, /temp <sec> <msg>, /fav <id>, /archive <id>,"
            " /export <file>, /import <file>, /nick <name>, /group <name>, /lang <code>, /exit"
        ),
        "enter_password": "Enter application password: ",
        "incorrect_password": "Incorrect password.",
        "listening_on": "Listening on {host}:{port}...",
        "peer_connected": "Peer connected from {host}:{port}",
        "connected_to": "Connected to peer {host}:{port}",
        "session_key": "Session key established.",
        "language_switched": "Language switched to {lang}",
        "available_languages": "Available languages: {langs}",
        "unknown_option": "Unknown option.",
        "contacts_header": "Contacts:",
        "no_contacts": "(no contacts)",
        "contact_prompt": "Select contact or command [add/remove/hide/unhide/theme/lang/exit]: ",
        "name_prompt": "Name: ",
        "identifier_prompt": "Identifier or IP address: ",
        "port_prompt": "Port (default {port}): ",
        "contact_added": "Contact {alias} added.",
        "name_remove": "Name to remove: ",
        "contact_removed": "Contact {alias} removed.",
        "contact_not_found": "Contact not found.",
        "name_hide": "Name to hide: ",
        "contact_hidden": "Contact {alias} hidden.",
        "name_unhide": "Name to unhide: ",
        "contact_unhidden": "Contact {alias} unhidden.",
        "choose_theme": "Choose theme (dark/light/auto): ",
        "unknown_theme": "Unknown theme.",
        "select_mode": "Select mode: 'direct' for IP chat or 'contacts': ",
        "enter_target": "Enter target IP or identifier: ",
        "authentication_failed": "Authentication failed.",
        "unknown_mode": "Unknown mode.",
        "usage_temp": "Usage: /temp <seconds> <message>",
        "invalid_seconds": "Invalid seconds.",
        "usage_emoji": "Usage: /emoji <alias>|add <alias> <path>|list",
        "unknown_emoji": "Unknown emoji: {alias}",
        "no_emojis": "(no emojis)",
        "emoji_added": "Emoji {alias} added.",
        "file_not_found": "File not found: {path}",
        "cannot_read_image": "Cannot read image: {path}",
        "sent_image": "[You #{id}] sent image {name}",
        "cannot_read_video": "Cannot read video: {path}",
        "sent_video": "[You #{id}] sent video {name}",
        "cannot_read_file": "Cannot read file: {path}",
        "sent_file": "[You #{id}] sent file {name}",
        "lang_prompt": "Language ({langs}): ",
        "your_identifier": "Your identifier: {id}",
    },
    "zh": {
        "startup_art": (
            "===================================\n"
            "||                               ||\n"
            "||           隧道聊天           ||\n"
            "||                               ||\n"
            "==================================="
        ),
        "press_enter": "按回车继续...",
        "banner_title": "=== 隧道聊天 ===",
        "command_hint": (
            "命令: /image <路径>, /video <路径>, /file <路径>, /emoji <别名>,"
            " /emoji add <别名> <路径>, /temp <秒> <消息>, /fav <ID>, /archive <ID>,"
            " /export <文件>, /import <文件>, /nick <昵称>, /group <名字>, /lang <代码>, /exit"
        ),
        "enter_password": "请输入应用密码：",
        "incorrect_password": "密码错误。",
        "listening_on": "正在监听 {host}:{port}...",
        "peer_connected": "对等方已连接，自 {host}:{port}",
        "connected_to": "已连接到对等方 {host}:{port}",
        "session_key": "会话密钥已建立。",
        "language_switched": "已切换语言为 {lang}",
        "available_languages": "可用语言: {langs}",
        "unknown_option": "未知选项。",
        "contacts_header": "联系人:",
        "no_contacts": "(暂无联系人)",
        "contact_prompt": "选择联系人或指令 [add/remove/hide/unhide/theme/lang/exit]: ",
        "name_prompt": "名称: ",
        "identifier_prompt": "识别码或IP地址: ",
        "port_prompt": "端口 (默认 {port}): ",
        "contact_added": "联系人 {alias} 已添加。",
        "name_remove": "要移除的名称: ",
        "contact_removed": "联系人 {alias} 已移除。",
        "contact_not_found": "未找到联系人。",
        "name_hide": "要隐藏的名称: ",
        "contact_hidden": "联系人 {alias} 已隐藏。",
        "name_unhide": "要取消隐藏的名称: ",
        "contact_unhidden": "联系人 {alias} 已显示。",
        "choose_theme": "选择主题 (dark/light/auto): ",
        "unknown_theme": "未知主题。",
        "select_mode": "选择模式: 直接IP聊天 'direct' 或联系人模式 'contacts': ",
        "enter_target": "输入目标IP或识别码: ",
        "authentication_failed": "认证失败。",
        "unknown_mode": "未知模式。",
        "usage_temp": "用法: /temp <秒数> <消息>",
        "invalid_seconds": "无效的秒数。",
        "usage_emoji": "用法: /emoji <别名>|add <别名> <路径>|list",
        "unknown_emoji": "未知表情: {alias}",
        "no_emojis": "(暂无表情)",
        "emoji_added": "表情 {alias} 已添加。",
        "file_not_found": "未找到文件: {path}",
        "cannot_read_image": "无法读取图片: {path}",
        "sent_image": "[你 #{id}] 已发送图片 {name}",
        "cannot_read_video": "无法读取视频: {path}",
        "sent_video": "[你 #{id}] 已发送视频 {name}",
        "cannot_read_file": "无法读取文件: {path}",
        "sent_file": "[你 #{id}] 已发送文件 {name}",
        "lang_prompt": "语言 ({langs}): ",
        "your_identifier": "你的识别码: {id}",
    },
}

CURRENT_LANG = "zh"
LANG = LANGUAGES[CURRENT_LANG]


def set_language(lang):
    global CURRENT_LANG, LANG
    if lang in LANGUAGES:
        CURRENT_LANG = lang
        LANG = LANGUAGES[lang]
    else:
        CURRENT_LANG = "en"
        LANG = LANGUAGES["en"]


def tr(key, **kwargs):
    return LANG.get(key, LANGUAGES["en"].get(key, key)).format(**kwargs)


def apply_theme(theme):
    """Apply a color theme by updating global ANSI codes."""
    global COLOR_INFO, COLOR_WARN, COLOR_ERROR, COLOR_INPUT, COLOR_RESET, CURRENT_THEME
    colors = THEMES.get(theme, THEMES["dark"])
    COLOR_INFO = colors["info"]
    COLOR_WARN = colors["warn"]
    COLOR_ERROR = colors["error"]
    COLOR_INPUT = colors["input"]
    COLOR_RESET = colors["reset"]
    CURRENT_THEME = theme


def pick_theme(choice):
    """Resolve a theme choice, handling automatic selection by time."""
    if choice == "auto":
        hour = time.localtime().tm_hour
        return "light" if 7 <= hour < 19 else "dark"
    return choice


def show_startup_screen():
    """Clear the terminal and display a startup splash."""
    os.system("cls" if os.name == "nt" else "clear")
    art = tr("startup_art")
    print(f"{COLOR_INFO}{art}{COLOR_RESET}")
    input(f"{COLOR_INPUT}{tr('press_enter')}{COLOR_RESET}")


def _print_banner_old():
    """Display a simple startup banner and command hint."""
    print(f"{COLOR_INFO}=== 隧道聊天 ==={COLOR_RESET}")
    print(
        "Commands: /image <path>, /video <path>, /file <path>, /emoji <alias>,"
        " /emoji add <alias> <path>, /temp <sec> <msg>, /fav <id>, /archive <id>,"
        " /export <file>, /import <file>, /nick <name>, /group <name>, /exit"
    )


def require_app_password():
    for _ in range(3):
        if getpass.getpass(tr("enter_password")) == APP_PASSWORD:
            return True
        print(f"{COLOR_ERROR}{tr('incorrect_password')}{COLOR_RESET}")
    return False

def generate_dh_key_pair():
    private_key = _DH_PARAMETERS.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def perform_key_exchange(sock, is_server=False):
    """Perform a Diffie-Hellman handshake on the given socket.

    When acting as a server, wait for the peer's public key before sending our
    own. As a client, send our key first. The resulting shared secret is
    stretched via HKDF and turned into a Fernet cipher for the session.
    """

    if is_server:
        client_pub = sock.recv(1024)
        client_key = load_der_public_key(client_pub)
        priv, pub = generate_dh_key_pair()
        sock.sendall(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        shared = priv.exchange(client_key)
    else:
        priv, pub = generate_dh_key_pair()
        sock.sendall(pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        server_pub = sock.recv(1024)
        server_key = load_der_public_key(server_pub)
        shared = priv.exchange(server_key)

    derived = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"handshake").derive(shared)
    return Fernet(base64.urlsafe_b64encode(derived))

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
    print(tr("your_identifier", id=user_id))
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
        while chunk := f.read(chunk_size):
            b64 = base64.b64encode(chunk).decode()
            send_encrypted(sock, f"{tag}CHUNK|{filename}|{b64}", session_cipher, local_cipher)
    send_encrypted(sock, f"{tag}END|{filename}", session_cipher, local_cipher)


def receive_messages(sock, session_cipher, local_cipher, history, state, expire_cb):
    """Continuously receive and process messages from the peer."""
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
    finally:
        for f in ongoing.values():
            try:
                f.close()
            except Exception:
                pass

def start_chat(host, port, name, listen=False):
    if listen:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"{COLOR_INFO}{tr('listening_on', host=host, port=port)}{COLOR_RESET}")
        client_socket, addr = server_socket.accept()
        server_socket.close()
        print(f"{COLOR_INFO}{tr('peer_connected', host=addr[0], port=addr[1])}{COLOR_RESET}")
    else:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        print(f"{COLOR_INFO}{tr('connected_to', host=host, port=port)}{COLOR_RESET}")

    session_cipher = perform_key_exchange(client_socket, is_server=listen)
    print(f"{COLOR_INFO}{tr('session_key')}{COLOR_RESET}")
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

    current_group = None

    try:
        while True:
            prompt = f"[{current_group}] " if current_group else ""
            message = input(f"{COLOR_INPUT}{prompt}> {COLOR_RESET}").strip()
            if message == "/exit":
                break

            if message.startswith("/emoji"):
                parts = message.split()
                if len(parts) == 1 or parts[1] == "list":
                    if emojis:
                        for alias in emojis:
                            print(f"  {alias} -> {emojis[alias]}")
                    else:
                        print(f"  {tr('no_emojis')}")
                elif parts[1] == "add" and len(parts) == 4:
                    alias, path = parts[2], parts[3]
                    if os.path.exists(path):
                        emojis[alias] = path
                        save_emojis(emojis)
                        print(f"{COLOR_INFO}{tr('emoji_added', alias=alias)}{COLOR_RESET}")
                    else:
                        print(f"{COLOR_ERROR}{tr('file_not_found', path=path)}{COLOR_RESET}")
                elif len(parts) == 2:
                    alias = parts[1]
                    path = emojis.get(alias)
                    if path and os.path.exists(path):
                        try:
                            with open(path, "rb") as img_file:
                                img_data = img_file.read()
                        except OSError:
                            print(f"{COLOR_ERROR}{tr('cannot_read_image', path=path)}{COLOR_RESET}")
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
                        print(f"{COLOR_WARN}{tr('unknown_emoji', alias=alias)}{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}{tr('usage_emoji')}{COLOR_RESET}")
            elif message.startswith("/temp "):
                parts = message.split(" ", 2)
                if len(parts) < 3:
                    print(f"{COLOR_WARN}{tr('usage_temp')}{COLOR_RESET}")
                    continue
                try:
                    ttl = int(parts[1])
                except ValueError:
                    print(f"{COLOR_ERROR}{tr('invalid_seconds')}{COLOR_RESET}")
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
            elif message.startswith("/group "):
                group = message.split(" ", 1)[1].strip()
                if group:
                    send_encrypted(client_socket, f"SYS|GROUP|{group}", session_cipher, local_cipher)
                    current_group = group
                    print(f"{COLOR_INFO}Joined group {group}{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}Usage: /group <name>{COLOR_RESET}")
            elif message.startswith("/theme"):
                parts = message.split()
                if len(parts) == 2 and parts[1] in ["dark", "light", "auto"]:
                    new_theme = pick_theme(parts[1])
                    apply_theme(new_theme)
                    print(f"{COLOR_INFO}Theme switched to {new_theme}.{COLOR_RESET}")
                else:
                    print(f"{COLOR_WARN}Usage: /theme <dark|light|auto>{COLOR_RESET}")
            elif message.startswith("/lang"):
                parts = message.split()
                if len(parts) == 2 and parts[1] in LANGUAGES:
                    set_language(parts[1])
                    print(f"{COLOR_INFO}{tr('language_switched', lang=parts[1])}{COLOR_RESET}")
                    print_banner()
                else:
                    print(
                        f"{COLOR_WARN}{tr('available_languages', langs=', '.join(LANGUAGES))}{COLOR_RESET}"
                    )
            elif message.startswith("/image "):
                path = message.split(" ", 1)[1]
                try:
                    with open(path, "rb") as img_file:
                        img_data = img_file.read()
                except OSError:
                    print(f"{COLOR_ERROR}{tr('cannot_read_image', path=path)}{COLOR_RESET}")
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
                print(
                    f"{COLOR_INFO}{tr('sent_image', id=msg_id, name=os.path.basename(path))}{COLOR_RESET}"
                )
            elif message.startswith("/video "):
                path = message.split(" ", 1)[1]
                if not os.path.exists(path):
                    print(f"{COLOR_ERROR}{tr('cannot_read_video', path=path)}{COLOR_RESET}")
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
                print(
                    f"{COLOR_INFO}{tr('sent_video', id=msg_id, name=os.path.basename(path))}{COLOR_RESET}"
                )
            elif message.startswith("/file "):
                path = message.split(" ", 1)[1]
                if not os.path.exists(path):
                    print(f"{COLOR_ERROR}{tr('cannot_read_file', path=path)}{COLOR_RESET}")
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
                print(
                    f"{COLOR_INFO}{tr('sent_file', id=msg_id, name=os.path.basename(path))}{COLOR_RESET}"
                )
            else:
                send_encrypted(client_socket, message, session_cipher, local_cipher)
                msg_id = next_id(state)
                history.append({"id": msg_id, "dir": "out", "text": message, "time": time.time()})
                print(f"{COLOR_INFO}[You #{msg_id}] {message}{COLOR_RESET}")
    except KeyboardInterrupt:
        print(f"{COLOR_WARN}Disconnected from peer.{COLOR_RESET}")
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
        print(f"\n{COLOR_INFO}{tr('contacts_header')}{COLOR_RESET}")
        visible = {k: v for k, v in contacts.items() if not v.get("hidden")}
        if visible:
            for alias, addr in visible.items():
                print(f"  - {alias}: {addr['host']}:{addr['port']}")
        else:
            print(f"  {tr('no_contacts')}")
        choice = input(
            f"{COLOR_INPUT}{tr('contact_prompt')}{COLOR_RESET}"
        ).strip()
        if choice == "add":
            alias = input(f"{COLOR_INPUT}{tr('name_prompt')}{COLOR_RESET}")
            token_or_ip = input(
                f"{COLOR_INPUT}{tr('identifier_prompt')}{COLOR_RESET}"
            ).strip()
            port_in = input(
                f"{COLOR_INPUT}{tr('port_prompt', port=default_port)}{COLOR_RESET}"
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
            print(f"{COLOR_INFO}{tr('contact_added', alias=alias)}{COLOR_RESET}")
        elif choice == "remove":
            alias = input(f"{COLOR_INPUT}{tr('name_remove')}{COLOR_RESET}")
            if alias in contacts:
                contacts.pop(alias)
                save_contacts(contacts)
                print(f"{COLOR_INFO}{tr('contact_removed', alias=alias)}{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}{tr('contact_not_found')}{COLOR_RESET}")
        elif choice == "hide":
            alias = input(f"{COLOR_INPUT}{tr('name_hide')}{COLOR_RESET}")
            if alias in contacts:
                contacts[alias]["hidden"] = True
                save_contacts(contacts)
                print(f"{COLOR_INFO}{tr('contact_hidden', alias=alias)}{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}{tr('contact_not_found')}{COLOR_RESET}")
        elif choice == "unhide":
            alias = input(f"{COLOR_INPUT}{tr('name_unhide')}{COLOR_RESET}")
            if alias in contacts:
                contacts[alias]["hidden"] = False
                save_contacts(contacts)
                print(f"{COLOR_INFO}{tr('contact_unhidden', alias=alias)}{COLOR_RESET}")
            else:
                print(f"{COLOR_WARN}{tr('contact_not_found')}{COLOR_RESET}")
        elif choice == "theme":
            t = input(f"{COLOR_INPUT}{tr('choose_theme')}{COLOR_RESET}").strip()
            if t in ["dark", "light", "auto"]:
                apply_theme(pick_theme(t))
            else:
                print(f"{COLOR_WARN}{tr('unknown_theme')}{COLOR_RESET}")
        elif choice == "lang":
            code = input(
                f"{COLOR_INPUT}{tr('lang_prompt', langs=', '.join(LANGUAGES))}{COLOR_RESET}"
            ).strip()
            if code in LANGUAGES:
                set_language(code)
                print(f"{COLOR_INFO}{tr('language_switched', lang=code)}{COLOR_RESET}")
            else:
                print(
                    f"{COLOR_WARN}{tr('available_languages', langs=', '.join(LANGUAGES))}{COLOR_RESET}"
                )
        elif choice == "exit":
            break
        elif choice in contacts:
            info = contacts[choice]
            start_chat(info['host'], info['port'], self_name)
        else:
            print(f"{COLOR_WARN}{tr('unknown_option')}{COLOR_RESET}")


def print_banner():
    """Display a simple startup banner and command hint."""
    print(f"{COLOR_INFO}{tr('banner_title')}{COLOR_RESET}")
    print(tr("command_hint"))


def main():
    parser = argparse.ArgumentParser(description="隧道聊天客户端")
    parser.add_argument("host", nargs="?", help="Peer IP or identifier for direct mode")
    parser.add_argument("--port", type=int, default=65432, help="Port to connect or listen on")
    parser.add_argument("--mode", choices=["direct", "contacts"], help="Chat mode")
    parser.add_argument(
        "--listen",
        action="store_true",
        help="Listen for an incoming connection in direct mode",
    )
    parser.add_argument(
        "--theme",
        choices=["auto", "dark", "light"],
        default="auto",
        help="Color theme (auto uses time of day)",
    )
    parser.add_argument(
        "--lang",
        choices=list(LANGUAGES.keys()),
        default="zh",
        help="UI language",
    )
    args = parser.parse_args()

    set_language(args.lang)
    apply_theme(pick_theme(args.theme))
    show_startup_screen()

    if not require_app_password():
        print(f"{COLOR_ERROR}{tr('authentication_failed')}{COLOR_RESET}")
        return

    user_id, name = load_or_create_profile(args.port)
    print(f"{COLOR_INFO}{tr('your_identifier', id=user_id)}{COLOR_RESET}")

    mode = args.mode
    if not mode:
        mode = (
            input(
                f"{COLOR_INPUT}{tr('select_mode')}{COLOR_RESET}"
            )
            .strip()
            .lower()
        )

    if mode == "direct":
        if args.listen:
            start_chat("0.0.0.0", args.port, name, listen=True)
        else:
            target = args.host or input(
                f"{COLOR_INPUT}{tr('enter_target')}{COLOR_RESET}"
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
        print(f"{COLOR_ERROR}{tr('unknown_mode')}{COLOR_RESET}")

if __name__ == "__main__":
    main()

