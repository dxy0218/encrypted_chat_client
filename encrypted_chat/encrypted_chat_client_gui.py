"""Tkinter GUI client for the encrypted chat with read receipts and recall."""

from __future__ import annotations

import argparse
import socket
import threading
from pathlib import Path
from tkinter import Tk, Entry, Button, END, DISABLED, Frame
from tkinter.scrolledtext import ScrolledText

try:
    from .lan_discovery import DEFAULT_DISCOVERY_PORT, discover_lan_relay
    from .messages import msg, read, recall
    from .protocol import (
        DEFAULT_KEY_FILE,
        Cipher,
        create_cipher,
        recv_encrypted,
        recv_frame,
        send_encrypted,
        send_frame,
    )
    from .session import E2EESession
except ImportError:  # pragma: no cover - keeps direct script execution working.
    from lan_discovery import DEFAULT_DISCOVERY_PORT, discover_lan_relay
    from messages import msg, read, recall
    from protocol import (
        DEFAULT_KEY_FILE,
        Cipher,
        create_cipher,
        recv_encrypted,
        recv_frame,
        send_encrypted,
        send_frame,
    )
    from session import E2EESession


def send_text(sock: socket.socket, mode: str, cipher: Cipher | None, text: str) -> None:
    if cipher is None:
        raise RuntimeError("encryption session is not ready")
    if mode == "shared":
        send_encrypted(sock, cipher, text.encode())
    else:
        if not isinstance(cipher, E2EESession):
            raise RuntimeError("end-to-end session is not ready")
        send_frame(sock, cipher.encrypt_payload(text.encode()))


class ChatClientGUI:
    def __init__(
        self,
        master: Tk,
        mode: str,
        host: str,
        port: int,
        key_files: list[str | Path] | str | Path,
        peer_alias: str,
        identity_store: Path,
        identity_key_path: Path,
        inbox_key_path: Path | None,
        pad_payloads: bool,
    ) -> None:
        self.master = master
        self.mode = mode
        self.peer_alias = peer_alias
        self.identity_store = identity_store
        self.identity_verified = mode == "shared"
        self.master.title("Encrypted Chat Client")
        self.master.geometry("500x400")

        self.text = ScrolledText(master, state=DISABLED, width=60, height=20)
        self.text.pack(padx=10, pady=10, fill="both", expand=True)

        input_frame = Frame(master)
        input_frame.pack(fill="x", padx=10, pady=(0, 10))

        self.entry = Entry(input_frame)
        self.entry.pack(side="left", expand=True, fill="x")
        self.entry.bind("<Return>", lambda _: self.send_message())
        self.entry.focus()

        self.send_btn = Button(input_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side="left", padx=(5, 0))

        verify_frame = Frame(master)
        verify_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.trust_btn = Button(verify_frame, text="Trust peer", command=self.trust_peer)
        self.trust_btn.pack(side="left")
        self.reject_btn = Button(verify_frame, text="Reject peer", command=self.reject_peer)
        self.reject_btn.pack(side="left", padx=(5, 0))
        self.untrust_btn = Button(verify_frame, text="Untrust peer", command=self.untrust_peer)
        self.untrust_btn.pack(side="left", padx=(5, 0))

        self.cipher: Cipher | None = create_cipher(key_files) if mode == "shared" else None
        self.e2ee_session = (
            E2EESession(
                identity_key_path,
                identity_store,
                peer_alias,
                pad_payloads=pad_payloads,
                inbox_key_path=inbox_key_path,
            )
            if mode == "e2ee"
            else None
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        self.msg_id = 0
        self.pending_reads: set[int] = set()
        self.sent_messages: dict[int, str] = {}
        self.received_messages: dict[int, str] = {}

        threading.Thread(target=self.receive_messages, daemon=True).start()
        if self.mode == "e2ee" and self.e2ee_session is not None:
            self.append_text(f"Your identity fingerprint: {self.e2ee_session.own_fingerprint}")
            self.append_text("Waiting for a peer to establish E2EE session...")
            send_frame(self.sock, self.e2ee_session.hello.encode())

    def append_text(self, line: str) -> str:
        self.text.config(state="normal")
        index = self.text.index(END)
        self.text.insert(END, line + "\n")
        self.text.config(state=DISABLED)
        return index

    def append_from_worker(self, line: str) -> None:
        self.master.after(0, self.append_text, line)

    def append_received_from_worker(self, msg_id: int, line: str) -> None:
        def append_and_track() -> None:
            self.received_messages[msg_id] = self.append_text(line)

        self.master.after(0, append_and_track)

    def replace_line(self, index: str, line: str) -> None:
        end = f"{int(index.split('.')[0]) + 1}.0"
        self.text.config(state="normal")
        self.text.delete(index, end)
        self.text.insert(index, line + "\n")
        self.text.config(state=DISABLED)

    def replace_from_worker(self, index: str, line: str) -> None:
        self.master.after(0, self.replace_line, index, line)

    def send_message(self) -> None:
        message = self.entry.get()
        if not message:
            return
        if self.mode == "e2ee" and (self.e2ee_session is None or self.e2ee_session.cipher is None):
            self.append_text("Peer identity is not verified. Trust the fingerprint before chatting.")
            self.entry.delete(0, END)
            return
        if self.mode == "e2ee" and self.e2ee_session is not None and not self.e2ee_session.identity_verified:
            self.append_text("Peer identity is not verified. Trust the fingerprint before chatting.")
            self.entry.delete(0, END)
            return
        if message.startswith("/recall "):
            try:
                rid = int(message.split(" ", 1)[1])
            except ValueError:
                self.append_text("Invalid message ID")
                self.entry.delete(0, END)
                return
            if rid in self.sent_messages:
                active_cipher = self.e2ee_session if self.mode == "e2ee" else self.cipher
                send_text(self.sock, self.mode, active_cipher, recall(rid))
                idx = self.sent_messages.pop(rid)
                self.replace_line(idx, "[message recalled]")
                self.append_text(f"You recalled message {rid}")
            else:
                self.append_text("Unknown message ID")
            self.entry.delete(0, END)
            return

        self.msg_id += 1
        self.pending_reads.add(self.msg_id)
        active_cipher = self.e2ee_session if self.mode == "e2ee" else self.cipher
        send_text(self.sock, self.mode, active_cipher, msg(self.msg_id, message))
        idx = self.append_text(f"You({self.msg_id}): {message} [sent]")
        self.sent_messages[self.msg_id] = idx
        self.entry.delete(0, END)

    def trust_peer(self) -> None:
        if self.e2ee_session is None or self.e2ee_session.peer_fingerprint is None:
            self.append_text("No peer fingerprint available yet.")
            return
        if self.e2ee_session.safety_phrase is not None:
            self.append_text(f"Confirm safety phrase first: {self.e2ee_session.safety_phrase}")
        fingerprint = self.e2ee_session.trust_peer()
        self.identity_verified = True
        self.append_text(f"Trusted {self.peer_alias}: {fingerprint}")

    def reject_peer(self) -> None:
        self.identity_verified = False
        self.append_text("Peer identity rejected. Chat disabled.")
        self.entry.config(state=DISABLED)
        self.send_btn.config(state=DISABLED)

    def untrust_peer(self) -> None:
        removed = self.e2ee_session.untrust_peer() if self.e2ee_session is not None else False
        self.identity_verified = False
        if removed:
            self.append_text(f"Removed trusted identity for {self.peer_alias}.")
        else:
            self.append_text(f"No trusted identity was stored for {self.peer_alias}.")

    def receive_messages(self) -> None:
        try:
            while True:
                if self.mode == "shared":
                    data = recv_encrypted(self.sock, self.cipher)
                else:
                    frame = recv_frame(self.sock)
                    if frame.startswith((b"HELLO2|", b"HELLO3|")):
                        try:
                            was_ready = self.e2ee_session.ready.is_set() if self.e2ee_session is not None else False
                            peer_info = (
                                self.e2ee_session.process_hello(frame.decode())
                                if self.e2ee_session is not None
                                else None
                            )
                        except Exception:
                            self.append_from_worker("Rejected peer hello: invalid identity signature.")
                            continue
                        if peer_info is not None and self.e2ee_session is not None:
                            self.identity_verified = peer_info.identity_verified
                            if not was_ready:
                                send_frame(self.sock, self.e2ee_session.hello.encode())
                            self.append_from_worker(
                                f"E2EE session ready. Peer identity fingerprint: {peer_info.fingerprint}"
                            )
                            self.append_from_worker(f"Safety code: {peer_info.safety_code}")
                            self.append_from_worker(f"Safety phrase: {peer_info.safety_phrase}")
                            if peer_info.identity_verified:
                                self.append_from_worker(f"Peer identity verified as {self.peer_alias}.")
                            else:
                                self.append_from_worker("Peer identity is NOT verified. Use Trust peer or Reject peer.")
                        continue
                    if not frame.startswith(b"E2EE|"):
                        continue
                    if self.e2ee_session is None or self.e2ee_session.cipher is None:
                        self.append_from_worker("Received encrypted data before E2EE session was ready.")
                        continue
                    data = self.e2ee_session.decrypt_payload_frame(frame)
                text = data.decode(errors="ignore")
                if text.startswith("READ|"):
                    msg_id = int(text.split("|", 1)[1])
                    if msg_id in self.pending_reads:
                        self.pending_reads.remove(msg_id)
                        self.append_from_worker(f"Peer read message {msg_id}")
                elif text.startswith("RECALL|"):
                    msg_id = int(text.split("|", 1)[1])
                    idx = self.received_messages.pop(msg_id, None)
                    if idx is not None:
                        self.replace_from_worker(idx, "[message recalled]")
                    else:
                        self.append_from_worker(f"Peer recalled message {msg_id}")
                elif text.startswith("MSG|"):
                    _, msg_id_str, content = text.split("|", 2)
                    self.append_received_from_worker(int(msg_id_str), f"Peer({msg_id_str}): {content}")
                    active_cipher = self.e2ee_session if self.mode == "e2ee" else self.cipher
                    send_text(self.sock, self.mode, active_cipher, read(msg_id_str))
                else:
                    self.append_from_worker(text)
        except Exception:
            self.append_from_worker("Connection closed.")
        finally:
            self.sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted chat GUI client")
    parser.add_argument(
        "--mode",
        choices=("e2ee", "shared"),
        default="e2ee",
        help="e2ee encrypts between clients; shared uses the server key relay",
    )
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=int, default=65432, help="server port")
    parser.add_argument("--lan-discover", action="store_true", help="try LAN relay discovery before connecting")
    parser.add_argument("--lan-discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT, help="UDP LAN discovery port")
    parser.add_argument("--lan-discovery-timeout", type=float, default=3.0, help="LAN discovery timeout in seconds")
    parser.add_argument("--peer-alias", default="default-peer", help="local name used to pin the peer fingerprint")
    parser.add_argument(
        "--identity-key",
        type=Path,
        default=Path.home() / ".encrypted_chat" / "identity_ed25519.key",
        help="persistent Ed25519 identity key file",
    )
    parser.add_argument(
        "--inbox-key",
        type=Path,
        default=None,
        help="persistent X25519 inbox key file for offline delivery",
    )
    parser.add_argument(
        "--identity-store",
        type=Path,
        default=Path.home() / ".encrypted_chat" / "trusted_peers.json",
        help="JSON file for trusted peer fingerprints",
    )
    parser.add_argument(
        "--key-file",
        action="append",
        dest="key_files",
        help="shared Fernet key file; repeat for multi-layer encryption",
    )
    parser.add_argument(
        "--pad-payloads",
        action="store_true",
        help="pad E2EE payloads before encryption; both peers must enable this",
    )
    args = parser.parse_args()

    host = args.host
    port = args.port
    if args.lan_discover:
        endpoint = discover_lan_relay(
            timeout_seconds=args.lan_discovery_timeout,
            discovery_port=args.lan_discovery_port,
            expected_mode=args.mode,
        )
        if endpoint is not None:
            host = endpoint.host
            port = endpoint.port

    root = Tk()
    ChatClientGUI(
        root,
        args.mode,
        host,
        port,
        args.key_files or DEFAULT_KEY_FILE,
        args.peer_alias,
        args.identity_store,
        args.identity_key,
        args.inbox_key,
        args.pad_payloads,
    )
    root.mainloop()


if __name__ == "__main__":
    main()
