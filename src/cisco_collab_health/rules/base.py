"""Health rule interfaces."""

from __future__ import annotations

from typing import Protocol

from cisco_collab_health.models.facts import AssessmentFacts
from cisco_collab_health.models.findings import HealthFinding


class HealthRule(Protocol):
    """Protocol implemented by health assessment rules."""

    rule_id: str

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        """Evaluate normalized facts and return findings."""
