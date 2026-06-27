# Platform Builds v0.01beta

The Python desktop protocol remains the source of truth for v0.01beta. Desktop
users should run packaged client executables, not source launch scripts.

## Windows

```powershell
python .\scripts\build_desktop_clients.py --platform-tag windows-x64
.\release\windows-x64\EncryptedChatClient.exe
.\release\windows-x64\EncryptedChatCLI.exe --help
```

## Linux

```bash
python3 scripts/build_desktop_clients.py --platform-tag linux-x64
./release/linux-x64/EncryptedChatClient
./release/linux-x64/EncryptedChatCLI --help
```

## macOS

```bash
python3 scripts/build_desktop_clients.py --platform-tag macos-arm64
./release/macos-arm64/EncryptedChatClient
./release/macos-arm64/EncryptedChatCLI --help
```

The GitHub Actions workflow `.github/workflows/build-desktop-clients.yml`
builds native Windows, Linux, and macOS client artifacts on the matching host
platforms. Python desktop applications should not be cross-compiled from
Windows for Linux/macOS because bundled GUI and crypto runtime dependencies are
platform-native.

## iOS and iPadOS 18.0+

Open `platforms/apple/EncryptedChatApple` in Xcode 16 or newer. The v0.01beta
SwiftUI shell includes Chat, Identity, Transport, and Settings tabs with the
mandatory identity verification state represented in the UI. Full wire-protocol
parity with the Python client remains the next Apple milestone.

## Test Commands

Windows virtual-environment validation:

```powershell
.\scripts\test_venv.ps1
```

Fast local smoke test:

```powershell
.\scripts\smoke_windows.ps1
```
