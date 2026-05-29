from __future__ import annotations

from ..schemas import SecurityEvent


class EventLog:
    """Security events observed during a request. Detection is a monitor that
    runs regardless of which defenses are enabled — you can detect an attack you
    don't block, and you should detect one you do."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    def add(self, e: SecurityEvent) -> None:
        self.events.append(e)

    def has(self, attack_class: str) -> bool:
        return any(e.attack_class == attack_class for e in self.events)

    def classes(self) -> list[str]:
        return sorted({e.attack_class for e in self.events})

    def __len__(self) -> int:
        return len(self.events)
