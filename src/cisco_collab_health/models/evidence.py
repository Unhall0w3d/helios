"""Evidence reference models for traceable assessment output."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class EvidenceRef:
    """Reference to source data that supports a finding or collector result."""

    source: str
    operation: str
    node: str | None = None
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    artifact_path: Path | None = None
    parser: str | None = None
    confidence: str = "medium"
