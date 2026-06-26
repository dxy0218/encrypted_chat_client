# Platform Builds v0.01beta

The Python desktop client remains the protocol source of truth for v0.01beta.
Platform launchers and the Apple SwiftUI shell are split under `platforms/`.

## Windows

```powershell
.\platforms\desktop\windows\start_server.ps1
.\platforms\desktop\windows\start_gui.ps1
```

## Linux

```bash
chmod +x platforms/desktop/linux/*.sh
./platforms/desktop/linux/start_server.sh
./platforms/desktop/linux/start_gui.sh
```

## macOS

```bash
chmod +x platforms/desktop/macos/*.command
./platforms/desktop/macos/start_server.command
./platforms/desktop/macos/start_gui.command
```

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
