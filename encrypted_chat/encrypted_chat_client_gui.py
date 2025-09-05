import os
import socket
import threading
import hashlib
import uuid
import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(__file__)
PASSWORD_FILE = os.path.join(BASE_DIR, "password.hash")
KEY_FILE = os.path.join(BASE_DIR, "key.key")
USER_ID_FILE = os.path.join(BASE_DIR, "user_id.txt")
HOST = "127.0.0.1"
PORT = 65432


def load_key():
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def save_password(password: str) -> None:
    with open(PASSWORD_FILE, "w") as f:
        f.write(hash_password(password))


def verify_password(password: str) -> bool:
    if not os.path.exists(PASSWORD_FILE):
        return False
    with open(PASSWORD_FILE, "r") as f:
        stored_hash = f.read().strip()
    return stored_hash == hash_password(password)


def get_user_id() -> str:
    if os.path.exists(USER_ID_FILE):
        with open(USER_ID_FILE, "r") as f:
            return f.read().strip()
    user_id = uuid.uuid4().hex
    with open(USER_ID_FILE, "w") as f:
        f.write(user_id)
    messagebox.showinfo(
        "User ID",
        f"Your user ID is {user_id}.\nPlease record it; it will only be displayed once.",
    )
    return user_id


def ask_new_password() -> str:
    pwd1 = simpledialog.askstring("Set Password", "Enter new password:", show="*")
    if not pwd1:
        return ""
    pwd2 = simpledialog.askstring("Set Password", "Confirm password:", show="*")
    if pwd1 != pwd2:
        messagebox.showerror("Error", "Passwords do not match.")
        return ask_new_password()
    save_password(pwd1)
    return pwd1


def prompt_for_password() -> str:
    pwd = simpledialog.askstring("Password", "Enter password:", show="*")
    if pwd is None:
        return ""
    if not verify_password(pwd):
        messagebox.showerror("Error", "Incorrect password.")
        return prompt_for_password()
    return pwd


class ChatClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Encrypted Chat Client")
        self.text_area = tk.Text(root, state="disabled", width=60, height=20)
        self.text_area.pack(padx=10, pady=10)
        self.entry = tk.Entry(root, width=50)
        self.entry.pack(padx=10, pady=(0, 10), fill="x")
        self.entry.bind("<Return>", self.send_message)
        tk.Button(root, text="Send", command=self.send_message).pack(padx=10, pady=(0, 10))

        menubar = tk.Menu(root)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Change Password", command=self.change_password)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        root.config(menu=menubar)

        self.socket = None
        self.cipher = None
        self.connect()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def connect(self) -> None:
        key = load_key()
        self.cipher = Fernet(key)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((HOST, PORT))
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self) -> None:
        while True:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                message = self.cipher.decrypt(data).decode()
                self.append_message(f"Server: {message}")
            except Exception:
                break

    def send_message(self, event=None) -> None:
        message = self.entry.get()
        if not message:
            return
        self.entry.delete(0, tk.END)
        try:
            encrypted_message = self.cipher.encrypt(message.encode())
            self.socket.send(encrypted_message)
            self.append_message(f"Me: {message}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def append_message(self, message: str) -> None:
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.config(state="disabled")

    def change_password(self) -> None:
        current = simpledialog.askstring("Change Password", "Current password:", show="*")
        if not current or not verify_password(current):
            messagebox.showerror("Error", "Incorrect password.")
            return
        new_pwd = simpledialog.askstring("Change Password", "New password:", show="*")
        if not new_pwd:
            return
        confirm = simpledialog.askstring("Change Password", "Confirm new password:", show="*")
        if new_pwd != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        save_password(new_pwd)
        messagebox.showinfo("Success", "Password changed.")

    def on_close(self) -> None:
        try:
            self.socket.close()
        except Exception:
            pass
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    if os.path.exists(PASSWORD_FILE):
        prompt_for_password()
    else:
        ask_new_password()
    get_user_id()
    ChatClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
