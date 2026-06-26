# CLI Usage

## E2EE Start

Start the relay server:

```powershell
python encrypted_chat/encrypted_chat_server.py --host 127.0.0.1 --port 65432
```

Start a CLI client in another terminal:

```powershell
python encrypted_chat/encrypted_chat_client.py --host 127.0.0.1 --port 65432
```

Start another client in a third terminal to complete the E2EE handshake. Each
client prints persistent identity fingerprints plus a shared safety code and
safety phrase after the session is established. Compare the phrase or peer
fingerprint over a trusted channel, then run `/trust`.

Use a specific local identity key file:

```powershell
python encrypted_chat/encrypted_chat_client.py --identity-key alice_identity.key --inbox-key alice_inbox.key
```

Use direct LAN peer mode without a relay:

```powershell
python encrypted_chat/encrypted_chat_client.py --direct-listen-host 0.0.0.0 --direct-listen-port 65432
python encrypted_chat/encrypted_chat_client.py --direct-connect 192.168.1.20:65432
```

By default, unverified peers cannot chat. For a short test-only grace period,
allow five warned messages:

```powershell
python encrypted_chat/encrypted_chat_client.py --unverified-policy limit
```

## Shared-Key Compatibility Mode

```powershell
python encrypted_chat/encrypted_chat_server.py --mode shared --key-file key.key
python encrypted_chat/encrypted_chat_client.py --mode shared --key-file key.key
```

For multi-layer shared-key encryption, repeat `--key-file` on the server and
every client:

```powershell
python encrypted_chat/encrypted_chat_server.py --mode shared --key-file outer.key --key-file inner.key
python encrypted_chat/encrypted_chat_client.py --mode shared --key-file outer.key --key-file inner.key
```

The key file order must match on both sides.

## Commands

- Type text and press Enter to send a message.
- `/trust` pins the current peer fingerprint under `--peer-alias`.
- `/untrust` removes the pinned fingerprint for `--peer-alias`.
- `/reject` rejects the current peer identity and disables chat.
- `/store <message>` stores an E2EE offline packet for the current peer.
- `/fetch` fetches E2EE offline packets addressed to your identity fingerprint.
- `/file <path>` sends a file and shows transfer progress.
- `/recall <message-id>` recalls one of your sent messages.
- `/exit` closes the client.
