"""Contact and multi-device identity records."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ContactDevice:
    device_id: str
    fingerprint: str
    label: str = ""
    trusted_at: float = field(default_factory=time.time)


@dataclass
class Contact:
    alias: str
    devices: dict[str, ContactDevice] = field(default_factory=dict)


class ContactBook:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.contacts = self._load()

    def trust_device(self, alias: str, device_id: str, fingerprint: str, label: str = "") -> ContactDevice:
        contact = self.contacts.setdefault(alias, Contact(alias=alias))
        device = ContactDevice(device_id=device_id, fingerprint=fingerprint, label=label)
        contact.devices[device_id] = device
        self._save()
        return device

    def untrust_device(self, alias: str, device_id: str) -> bool:
        contact = self.contacts.get(alias)
        if contact is None:
            return False
        removed = contact.devices.pop(device_id, None) is not None
        if not contact.devices:
            self.contacts.pop(alias, None)
        if removed:
            self._save()
        return removed

    def trusted_fingerprints(self, alias: str) -> set[str]:
        contact = self.contacts.get(alias)
        if contact is None:
            return set()
        return {device.fingerprint for device in contact.devices.values()}

    def is_trusted(self, alias: str, fingerprint: str) -> bool:
        return fingerprint in self.trusted_fingerprints(alias)

    def _load(self) -> dict[str, Contact]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        contacts: dict[str, Contact] = {}
        for alias, contact_payload in payload.items():
            contact = Contact(alias=alias)
            for device_id, device_payload in contact_payload.get("devices", {}).items():
                contact.devices[device_id] = ContactDevice(
                    device_id=device_id,
                    fingerprint=str(device_payload["fingerprint"]),
                    label=str(device_payload.get("label", "")),
                    trusted_at=float(device_payload.get("trusted_at", 0)),
                )
            contacts[alias] = contact
        return contacts

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            alias: {
                "devices": {
                    device_id: {
                        "fingerprint": device.fingerprint,
                        "label": device.label,
                        "trusted_at": device.trusted_at,
                    }
                    for device_id, device in contact.devices.items()
                }
            }
            for alias, contact in self.contacts.items()
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
