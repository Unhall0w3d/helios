"""Health finding models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingSeverity(str, Enum):
    """Severity assigned to a health finding."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RecommendationKind(str, Enum):
    """Classification for the recommendation behind a finding."""

    REQUIREMENT = "requirement"
    BEST_PRACTICE = "best_practice"
    ENGINEERING_RECOMMENDATION = "engineering_recommendation"
    INFORMATIONAL = "informational"


@dataclass(frozen=True)
class HealthFinding:
    """A rule result with facts, reasoning, and recommendation metadata."""

    rule_id: str
    title: str
    severity: FindingSeverity
    recommendation_kind: RecommendationKind
    facts: list[str]
    reasoning: str
    recommendation: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
