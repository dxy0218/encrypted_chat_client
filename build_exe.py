"""Utility to build a Windows .exe for 隧道聊天.

Run `python build_exe.py` on a system with PyInstaller installed to
create `dist/隧道聊天.exe` which can be distributed to
users without a Python interpreter.
"""
from pathlib import Path
import PyInstaller.__main__


def main() -> None:
    client_script = Path('encrypted_chat/encrypted_chat_client_with_handshake.py')
    PyInstaller.__main__.run([
        str(client_script),
        '--onefile',
        '--name', '隧道聊天'
    ])


if __name__ == '__main__':
    main()
