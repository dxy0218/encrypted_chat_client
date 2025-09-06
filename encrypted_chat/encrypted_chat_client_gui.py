"""Tkinter GUI client for the encrypted chat with read receipts and recall."""

from __future__ import annotations

import socket
import struct
import threading
from pathlib import Path
from tkinter import Tk, Entry, Button, END, DISABLED, Frame
from tkinter.scrolledtext import ScrolledText

from cryptography.fernet import Fernet


def load_key() -> bytes:
    key_path = Path("key.key")
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    return key_path.read_bytes()


def send_encrypted(sock: socket.socket, cipher: Fernet, data: bytes) -> None:
    encrypted = cipher.encrypt(data)
    sock.sendall(struct.pack("!I", len(encrypted)))
    sock.sendall(encrypted)


def recv_encrypted(sock: socket.socket, cipher: Fernet) -> bytes:
    header = sock.recv(4)
    if len(header) < 4:
        raise ConnectionError("connection closed")
    (size,) = struct.unpack("!I", header)
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return cipher.decrypt(data)


def send_text(sock: socket.socket, cipher: Fernet, text: str) -> None:
    send_encrypted(sock, cipher, text.encode())


class ChatClientGUI:
    def __init__(self, master: Tk) -> None:
        self.master = master
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

        self.cipher = Fernet(load_key())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(("127.0.0.1", 65432))

        self.msg_id = 0
        self.pending_reads: set[int] = set()
        self.sent_messages: dict[int, str] = {}
        self.received_messages: dict[int, str] = {}

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def append_text(self, line: str) -> str:
        self.text.config(state="normal")
        index = self.text.index(END)
        self.text.insert(END, line + "\n")
        self.text.config(state=DISABLED)
        return index

    def replace_line(self, index: str, line: str) -> None:
        end = f"{int(index.split('.')[0]) + 1}.0"
        self.text.config(state="normal")
        self.text.delete(index, end)
        self.text.insert(index, line + "\n")
        self.text.config(state=DISABLED)

    def send_message(self) -> None:
        message = self.entry.get()
        if not message:
            return
        if message.startswith("/recall "):
            try:
                rid = int(message.split(" ", 1)[1])
            except ValueError:
                self.append_text("Invalid message ID")
                self.entry.delete(0, END)
                return
            if rid in self.sent_messages:
                send_text(self.sock, self.cipher, f"RECALL|{rid}")
                idx = self.sent_messages.pop(rid)
                self.replace_line(idx, "[message recalled]")
                self.append_text(f"You recalled message {rid}")
            else:
                self.append_text("Unknown message ID")
            self.entry.delete(0, END)
            return

        self.msg_id += 1
        self.pending_reads.add(self.msg_id)
        send_text(self.sock, self.cipher, f"MSG|{self.msg_id}|{message}")
        idx = self.append_text(f"You({self.msg_id}): {message} [sent]")
        self.sent_messages[self.msg_id] = idx
        self.entry.delete(0, END)

    def receive_messages(self) -> None:
        try:
            while True:
                data = recv_encrypted(self.sock, self.cipher)
                text = data.decode(errors="ignore")
                if text.startswith("READ|"):
                    msg_id = int(text.split("|", 1)[1])
                    if msg_id in self.pending_reads:
                        self.pending_reads.remove(msg_id)
                        self.append_text(f"Peer read message {msg_id}")
                elif text.startswith("RECALL|"):
                    msg_id = int(text.split("|", 1)[1])
                    idx = self.received_messages.pop(msg_id, None)
                    if idx is not None:
                        self.replace_line(idx, "[message recalled]")
                    else:
                        self.append_text(f"Peer recalled message {msg_id}")
                elif text.startswith("MSG|"):
                    _, msg_id_str, content = text.split("|", 2)
                    idx = self.append_text(f"Peer({msg_id_str}): {content}")
                    self.received_messages[int(msg_id_str)] = idx
                    send_text(self.sock, self.cipher, f"READ|{msg_id_str}")
                else:
                    self.append_text(text)
        except Exception:
            self.append_text("Connection closed.")
        finally:
            self.sock.close()


def main() -> None:
    root = Tk()
    ChatClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
