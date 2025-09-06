# Windows Installer Guide

To package the encrypted chat client for Windows, run the provided setup script.
It checks for a Python environment, installs missing components (using winget or
Chocolatey when available), and then builds the installer. Missing Python
dependencies and PyInstaller are fetched automatically before the build starts.
The script supports Windows 7, 8, 10, and 11, and works with Python versions
3.8 through 3.12.

## Steps
1. Clone or download this repository and open **PowerShell** in its directory.
2. Run the setup script (optionally specify a Python version):

   ```powershell
   .\setup_env.ps1 -PythonVersion 3.11
   ```

   The script ensures the requested Python version is installed (falling back to
   the latest if omitted), installs project dependencies, generates a standalone
   executable, and packages it into an installer.

The process produces `EncryptedChatClientSetup.exe`, which guides users through
selecting an install directory and installs the `encrypted_chat_client.exe`
and `encrypted_chat_client_gui.exe` binaries.

After installation, two shortcuts are added to the Start Menu:
- **Encrypted Chat Client (CLI)** 打开命令提示符界面
- **Encrypted Chat Client (GUI)** 打开窗口界面
