$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv-test"
if (!(Test-Path $Venv)) {
  python -m venv $Venv
}
& (Join-Path $Venv "Scripts\python.exe") -m pip install --upgrade pip
& (Join-Path $Venv "Scripts\python.exe") -m pip install -r (Join-Path $Root "requirements.txt")
& (Join-Path $Venv "Scripts\python.exe") -m unittest discover -s (Join-Path $Root "tests")
& (Join-Path $Venv "Scripts\python.exe") -m compileall (Join-Path $Root "encrypted_chat") (Join-Path $Root "tests") (Join-Path $Root "build_windows_installer.py")
