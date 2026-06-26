# Encrypted Chat Client

A small Python chat demo with a relay server, end-to-end encrypted CLI chat,
and a simple Tkinter GUI client.

By default, clients use a persistent Ed25519 identity key to sign an ephemeral
X25519 session key exchange through the relay. Chat messages, read receipts,
recalls, and file payloads are encrypted on the sending client and decrypted
only by the receiving client. The server forwards opaque frames and cannot
decrypt E2EE messages.

## Features

- Default end-to-end encryption mode using X25519 plus HKDF-derived Fernet keys
- Persistent Ed25519 identity keys that sign each ephemeral E2EE handshake
- Mandatory peer identity verification with local fingerprint pinning
- Shared safety code and safety phrase for easier out-of-band verification
- Optional five-message unverified grace mode with warning labels
- Compatibility mode for shared-key relay encryption
- Optional multi-layer shared-key encryption by passing more than one `--key-file`
- CLI chat with read receipts, message recall, latency pings, and file transfer
- Tkinter GUI chat client
- LAN relay discovery with internet relay fallback
- Durable encrypted packet store for offline delivery workflows
- Relay store-and-forward commands for opaque E2EE packets
- Direct LAN peer listener/connector foundation
- Payload padding helpers for message size reduction
- Contact book foundation with multiple trusted devices per contact
- Shared protocol helpers and basic protocol tests

## Requirements

- Python 3.10+
- `cryptography`
- `colorama`

Current version: `v0.01beta`.

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run E2EE Mode

Start the relay server:

```powershell
python encrypted_chat/encrypted_chat_server.py --host 127.0.0.1 --port 65432
```

Start two CLI clients in separate terminals:

```powershell
python encrypted_chat/encrypted_chat_client.py --host 127.0.0.1 --port 65432
```

Each client prints its own fingerprint, the peer fingerprint, a safety code, and
a safety phrase once the E2EE session is ready. The fingerprint comes from the
persistent identity key, not from the temporary session key. Compare the safety
phrase or fingerprint over a trusted channel, then run:

```powershell
/trust
```

Reject a suspicious peer with:

```powershell
/reject
```

Remove a previously trusted fingerprint with:

```powershell
/untrust
```

Use a specific local identity key file:

```powershell
python encrypted_chat/encrypted_chat_client.py --identity-key alice_identity.key --inbox-key alice_inbox.key
```

By default, unverified peers cannot chat. For testing, allow up to five warned
messages with:

```powershell
python encrypted_chat/encrypted_chat_client.py --unverified-policy limit
```

Those messages are prefixed with an authenticity warning before encryption.

Start the GUI client:

```powershell
python encrypted_chat/encrypted_chat_client_gui.py --host 127.0.0.1 --port 65432
```

## Platform Launchers

Desktop launchers for Windows, Linux, and macOS plus the iOS/iPadOS 18.0+
SwiftUI v0.01beta shell are documented in `PLATFORMS.md`.

## LAN Discovery

Advertise a relay on the local network:

```powershell
python encrypted_chat/encrypted_chat_server.py --lan-advertise --lan-advertise-host 192.168.1.20
```

Let a client discover a LAN relay before falling back to `--host` and `--port`:

```powershell
python encrypted_chat/encrypted_chat_client.py --lan-discover --host relay.example.com --port 65432
```

Use direct LAN peer mode without a relay:

```powershell
python encrypted_chat/encrypted_chat_client.py --direct-listen-host 0.0.0.0 --direct-listen-port 65432
python encrypted_chat/encrypted_chat_client.py --direct-connect 192.168.1.20:65432
```

## Metadata Padding

Both peers can opt into payload padding before E2EE encryption:

```powershell
python encrypted_chat/encrypted_chat_client.py --pad-payloads
```

Both sides must use the same padding setting for a session.

## Offline Store-And-Forward

Run the relay with an encrypted packet store:

```powershell
python encrypted_chat/encrypted_chat_server.py --offline-store relay_packets.jsonl
```

In the CLI, after an E2EE session is established, store an opaque encrypted
packet for the current peer's persistent inbox key:

```powershell
/store hello while you were offline
```

Fetch packets addressed to your own identity fingerprint:

```powershell
/fetch
```

The relay stores only opaque E2EE frames keyed by recipient fingerprint.
Recipients can decrypt stored packets after restart as long as their persistent
inbox key is preserved.

## Shared-Key Compatibility Mode

The previous shared-key relay design is still available:

```powershell
python encrypted_chat/encrypted_chat_server.py --mode shared --key-file key.key
python encrypted_chat/encrypted_chat_client.py --mode shared --key-file key.key
python encrypted_chat/encrypted_chat_client_gui.py --mode shared --key-file key.key
```

Use multiple Fernet key files for nested shared-key encryption:

```powershell
python encrypted_chat/encrypted_chat_server.py --mode shared --key-file outer.key --key-file inner.key
python encrypted_chat/encrypted_chat_client.py --mode shared --key-file outer.key --key-file inner.key
python encrypted_chat/encrypted_chat_client_gui.py --mode shared --key-file outer.key --key-file inner.key
```

Both sides must pass the same key files in the same order. Encryption is applied
from left to right, and decryption is applied in reverse order.

## CLI Commands

- `/trust` pins the current peer fingerprint under `--peer-alias`
- `/untrust` removes the pinned fingerprint for `--peer-alias`
- `/reject` rejects the current peer identity and disables chat
- `/file <path>` sends a file to connected peers
- `/recall <message-id>` recalls one of your sent messages
- `/exit` exits the client

## Development Roadmap

1. Stabilize identity: persistent local client identity keys, safety phrase
   comparison, and safer trust reset flows are implemented; QR export remains
   next.
2. Split the app into layers: crypto/session, message queue, transport, and UI
   foundations are implemented.
3. Add LAN-first transport: UDP LAN relay discovery and fallback are
   implemented; direct peer listener/connector foundations are implemented.
4. Add offline delivery: durable encrypted packet storage with TTL and
   deduplication is implemented; relay store-and-forward commands and CLI hooks
   are implemented.
5. Add metadata reduction: optional E2EE payload padding is implemented;
   batching, randomized retry timing, and relay rotation remain next.
6. Add stronger multi-device/contact management before attempting group chat:
   contact book foundations with multiple trusted devices are implemented.

## Tests

```powershell
python -m unittest discover -s tests
```

## Security Notes

- E2EE mode protects message contents from the relay server.
- E2EE mode is designed for a two-client session; full group key management is
  not implemented.
- Peer identity is pinned locally after `/trust`; compare persistent identity
  fingerprints or safety phrases before trusting to reduce man-in-the-middle
  risk.
- The E2EE session key is ephemeral and is not persisted.
- Shared-key mode is not end-to-end encryption because the relay server owns the
  shared key files and can decrypt messages.
- This is still a learning demo, not a production secure messenger.
