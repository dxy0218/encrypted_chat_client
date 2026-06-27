"""Small in-memory message queue used before transport-specific delivery."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class QueuedMessage:
    message_id: int
    payload: bytes
    created_at: float = field(default_factory=time.time)
    attempts: int = 0
    sent: bool = False


class MessageQueue:
    def __init__(self) -> None:
        self._next_id = 1
        self._messages: dict[int, QueuedMessage] = {}

    def enqueue(self, payload: bytes) -> QueuedMessage:
        message = QueuedMessage(message_id=self._next_id, payload=payload)
        self._messages[message.message_id] = message
        self._next_id += 1
        return message

    def mark_attempted(self, message_id: int) -> None:
        self._messages[message_id].attempts += 1

    def mark_sent(self, message_id: int) -> None:
        self._messages[message_id].sent = True

    def pending(self) -> list[QueuedMessage]:
        return [message for message in self._messages.values() if not message.sent]

    def remove(self, message_id: int) -> bool:
        return self._messages.pop(message_id, None) is not None
