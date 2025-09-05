# Windows Installer Guide

This project contains simple Python scripts for an encrypted chat client. To distribute the client on Windows, a standalone executable and installer can be built automatically.

## 1. Prepare the environment
1. [Install Python](https://www.python.org/downloads/windows/) (3.8+).
2. Clone or download this repository.
3. Open **PowerShell** and set up a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Ensure [PyInstaller](https://pyinstaller.org/) and [Inno Setup](https://jrsoftware.org/isinfo.php) are installed and available on `PATH`.

## 2. Build executable and installer

Run the automation script:

```powershell
python build_windows_installer.py
```

The script creates `dist\encrypted_chat_client.exe` and packages it with Inno Setup to produce `EncryptedChatClientSetup.exe`.

## 3. Run the client

After installation, users can launch the "Encrypted Chat Client" from the Start Menu or by running the installed `.exe` directly.
