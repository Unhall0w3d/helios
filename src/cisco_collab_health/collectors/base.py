"""Collector interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from cisco_collab_health.models.facts import AssessmentFacts


@dataclass(frozen=True)
class CollectionContext:
    """Shared context passed to collectors."""

    target: str | None = None
    username: str | None = None
    publisher_ip: str | None = None
    gui_username: str | None = None
    gui_password: str | None = field(default=None, repr=False)
    os_username: str | None = None
    os_password: str | None = field(default=None, repr=False)
    timeout_seconds: int = 30


@dataclass(frozen=True)
class CollectionResult:
    """Facts and metadata returned by one collector."""

    collector_name: str
    facts: AssessmentFacts
    warnings: list[str] = field(default_factory=list)


class Collector(Protocol):
    """Protocol implemented by all fact collectors."""

    name: str

    def collect(self, context: CollectionContext) -> CollectionResult:
        """Collect facts from a Cisco Collaboration source."""
