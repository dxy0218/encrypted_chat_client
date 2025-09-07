#!/usr/bin/env python3
"""Automation script to build the Windows executable and installer."""

from __future__ import annotations

import importlib.util
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"


def check_environment() -> None:
    """Ensure the script is running on a supported platform."""
    if platform.system() != "Windows":
        raise RuntimeError("Windows build script must be run on a Windows host")

    win_version = platform.release()
    print(f"Detected Windows version: {win_version}")

    if sys.version_info < (3, 8):
        raise RuntimeError("Python 3.8 or newer is required to build the installer")
    print(f"Using Python {platform.python_version()}")


def run(cmd: list[str]) -> None:
    """Run a command and raise with context if it fails."""
    print("Running:", " ".join(cmd))
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, file=sys.stderr)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, cmd)


def ensure_requirements() -> None:
    """Install missing project requirements and PyInstaller."""
    req_file = ROOT / "requirements.txt"
    to_install: list[str] = []

    if req_file.exists():
        for line in req_file.read_text().splitlines():
            pkg = line.strip()
            if not pkg or pkg.startswith("#"):
                continue
            module = re.split(r"[<>=]", pkg, 1)[0]
            if importlib.util.find_spec(module) is None:
                to_install.append(pkg)

    if shutil.which("pyinstaller") is None:
        to_install.append("pyinstaller")

    if to_install:
        print("Installing Python requirements and PyInstaller...")
        run([sys.executable, "-m", "pip", "install", *to_install])
    else:
        print("All required Python packages are already installed.")


def clean_artifacts() -> None:
    """Remove old build artifacts to avoid conflicts."""
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    iss = ROOT / "installer.iss"
    if iss.exists():
        iss.unlink()


def ensure_iscc() -> None:
    """Ensure the Inno Setup compiler is available."""
    if shutil.which('iscc') is not None:
        return

    if sys.platform != 'win32':
        raise RuntimeError(
            'iscc (Inno Setup compiler) not found and automatic installation is only supported on Windows.',
        )

    url = 'https://jrsoftware.org/download.php/is.exe'
    installer = ROOT / 'is.exe'
    print('Downloading Inno Setup...')
    urllib.request.urlretrieve(url, installer)
    print('Installing Inno Setup...')
    run([str(installer), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'])
    installer.unlink(missing_ok=True)
    if shutil.which('iscc') is None:
        raise RuntimeError(
            'iscc (Inno Setup compiler) not found after installation. Please ensure it is on PATH.',
        )

def build_executable() -> None:
    """Build both console and GUI executables using PyInstaller."""
    run(
        [
            "pyinstaller",
            "--onefile",
            str(ROOT / "encrypted_chat" / "encrypted_chat_client.py"),
        ]
    )
    run(
        [
            "pyinstaller",
            "--onefile",
            "--windowed",
            str(ROOT / "encrypted_chat" / "encrypted_chat_client_gui.py"),
        ]
    )


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
Source: "{DIST_DIR}\\encrypted_chat_client_gui.exe"; DestDir: "{{app}}"; Flags: ignoreversion

[Icons]
Name: "{{autoprograms}}\\Encrypted Chat Client (CLI)"; Filename: "{{app}}\\encrypted_chat_client.exe"
Name: "{{autoprograms}}\\Encrypted Chat Client (GUI)"; Filename: "{{app}}\\encrypted_chat_client_gui.exe"
""".strip()
    iss_path.write_text(iss_content)
    return iss_path


def build_installer(iss_path: Path) -> None:
    """Compile the Inno Setup script."""
    run(["iscc", str(iss_path)])
    iss_path.unlink(missing_ok=True)


if __name__ == "__main__":
    check_environment()
    clean_artifacts()
    ensure_requirements()
    ensure_iscc()
    build_executable()
    iss = create_inno_script()
    build_installer(iss)
    print("Installer built: EncryptedChatClientSetup.exe")
