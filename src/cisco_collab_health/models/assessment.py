"""Top-level assessment result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from typing import TYPE_CHECKING

from cisco_collab_health.models.facts import AssessmentFacts
from cisco_collab_health.models.findings import HealthFinding

if TYPE_CHECKING:
    from cisco_collab_health.collectors.base import CollectionResult


@dataclass(frozen=True)
class AssessmentReport:
    """Complete result of one assessment run."""

    facts: AssessmentFacts
    collector_results: list[CollectionResult]
    findings: list[HealthFinding]
    runtime_metadata: dict[str, Any] = field(default_factory=dict)
