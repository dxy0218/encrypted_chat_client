# Windows Installer Guide

This project contains simple Python scripts for an encrypted chat client. To distribute the client on Windows with a graphical installer, build a standalone executable and wrap it in an installer package.

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

## 2. Build a standalone executable
1. Install PyInstaller:
   ```powershell
   pip install pyinstaller
   ```
2. Build the client executable:
   ```powershell
   pyinstaller --onefile encrypted_chat\encrypted_chat_client.py
   ```
   The executable will be generated at `dist\encrypted_chat_client.exe`.

## 3. Create an installer
The executable can be packaged into a Windows installer using [Inno Setup](https://jrsoftware.org/isinfo.php).

1. Install Inno Setup and create a script (e.g. `installer.iss`) with the following content:
   ```inno
   [Setup]
   AppName=Encrypted Chat Client
   AppVersion=1.0
   DefaultDirName={autopf}\EncryptedChatClient
   OutputBaseFilename=EncryptedChatClientSetup

   [Files]
   Source: "dist\encrypted_chat_client.exe"; DestDir: "{app}"; Flags: ignoreversion

   [Icons]
   Name: "{autoprograms}\Encrypted Chat Client"; Filename: "{app}\encrypted_chat_client.exe"
   ```
2. Compile the script in Inno Setup to produce `EncryptedChatClientSetup.exe`.
3. Running the installer lets users choose an installation directory and provides a shortcut to the executable.

## 4. Run the client
After installation, users can launch the "Encrypted Chat Client" from the Start Menu or by running the installed `.exe` directly.

