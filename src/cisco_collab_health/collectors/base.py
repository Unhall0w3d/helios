"""Collector interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import AssessmentFacts


@dataclass(frozen=True)
class TlsPolicy:
    """TLS verification behavior for HTTPS probes and collectors."""

    verify: bool = False
    ca_bundle: Path | None = None


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
    artifact_store: Any | None = field(default=None, repr=False)
    tls: TlsPolicy = field(default_factory=TlsPolicy)
    axl_port: int = 8443
    risport_port: int = 8443
    control_center_port: int = 8443
    perfmon_port: int = 8443


@dataclass(frozen=True)
class CollectorError:
    """Structured error raised by one collector without aborting the assessment."""

    message: str
    exception_type: str
    recoverable: bool = True


@dataclass(frozen=True)
class CollectionResult:
    """Facts and metadata returned by one collector."""

    collector_name: str
    facts: AssessmentFacts
    warnings: list[str] = field(default_factory=list)
    errors: list[CollectorError] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)


class Collector(Protocol):
    """Protocol implemented by all fact collectors."""

    name: str

    def collect(self, context: CollectionContext) -> CollectionResult:
        """Collect facts from a Cisco Collaboration source."""
