#!/usr/bin/env sh
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)"
cd "$ROOT"
python3 encrypted_chat/encrypted_chat_client_gui.py "$@"
