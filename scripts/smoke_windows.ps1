$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m unittest discover -s tests
python -m compileall encrypted_chat tests build_windows_installer.py
