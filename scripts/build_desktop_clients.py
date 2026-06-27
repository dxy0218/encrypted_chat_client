#!/usr/bin/env python3
"""Build desktop client executables for the current host platform."""

from __future__ import annotations

import argparse
import importlib.util
import platform
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = ROOT / "build" / "desktop"
RELEASE_ROOT = ROOT / "release"


def run(cmd: list[str]) -> None:
    print("Running:", " ".join(cmd))
    completed = subprocess.run(cmd, cwd=ROOT, text=True)
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, cmd)


def ensure_pyinstaller() -> None:
    if importlib.util.find_spec("PyInstaller") is not None:
        return
    run([sys.executable, "-m", "pip", "install", "pyinstaller"])


def platform_id() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower().replace("amd64", "x64").replace("x86_64", "x64")
    if system == "darwin":
        system = "macos"
    return f"{system}-{machine}"


def exe_name(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


def build_one(name: str, entry: Path, windowed: bool, out_dir: Path, work_dir: Path) -> None:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--paths",
        str(ROOT),
        "--name",
        name,
        "--distpath",
        str(out_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(work_dir),
    ]
    if windowed:
        cmd.append("--windowed")
    cmd.append(str(entry))
    run(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build desktop client executables")
    parser.add_argument("--platform-tag", default=platform_id(), help="release subdirectory name")
    parser.add_argument("--skip-deps", action="store_true", help="skip dependency installation")
    args = parser.parse_args()

    if not args.skip_deps:
        run([sys.executable, "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])
    ensure_pyinstaller()

    out_dir = RELEASE_ROOT / args.platform_tag
    work_dir = BUILD_ROOT / args.platform_tag
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    build_one(
        "EncryptedChatClient",
        ROOT / "scripts" / "desktop_gui.py",
        windowed=True,
        out_dir=out_dir,
        work_dir=work_dir,
    )
    build_one(
        "EncryptedChatCLI",
        ROOT / "scripts" / "desktop_cli.py",
        windowed=False,
        out_dir=out_dir,
        work_dir=work_dir,
    )

    print("Built desktop clients:")
    print(out_dir / exe_name("EncryptedChatClient"))
    print(out_dir / exe_name("EncryptedChatCLI"))


if __name__ == "__main__":
    main()
