#!/usr/bin/env python3
"""Automation script to build the Windows executable and installer."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"


def run(cmd: list[str]) -> None:
    """Run a command and raise if it fails."""
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def ensure_pyinstaller() -> None:
    """Ensure PyInstaller is available."""
    if shutil.which("pyinstaller") is None:
        print("PyInstaller not found, installing via pip...")
        run([sys.executable, "-m", "pip", "install", "pyinstaller"])


def ensure_iscc() -> None:
    """Ensure the Inno Setup compiler is available."""
    if shutil.which("iscc") is None:
        raise RuntimeError(
            "iscc (Inno Setup compiler) not found. Install Inno Setup and ensure 'iscc' is on PATH."
        )


def build_executable() -> None:
    """Build the standalone executable using PyInstaller."""
    run([
        "pyinstaller",
        "--onefile",
        str(ROOT / "encrypted_chat" / "encrypted_chat_client.py"),
    ])


def create_inno_script() -> Path:
    """Create the Inno Setup script for packaging."""
    iss_path = ROOT / "installer.iss"
    iss_content = f"""
[Setup]
AppName=Encrypted Chat Client
AppVersion=1.0
DefaultDirName={{autopf}}\\EncryptedChatClient
OutputBaseFilename=EncryptedChatClientSetup

[Files]
Source: "{DIST_DIR}\\encrypted_chat_client.exe"; DestDir: "{{app}}"; Flags: ignoreversion

[Icons]
Name: "{{autoprograms}}\\Encrypted Chat Client"; Filename: "{{app}}\\encrypted_chat_client.exe"
""".strip()
    iss_path.write_text(iss_content)
    return iss_path


def build_installer(iss_path: Path) -> None:
    """Compile the Inno Setup script."""
    run(["iscc", str(iss_path)])


if __name__ == "__main__":
    ensure_pyinstaller()
    ensure_iscc()
    build_executable()
    iss = create_inno_script()
    build_installer(iss)
    print("Installer built: EncryptedChatClientSetup.exe")
