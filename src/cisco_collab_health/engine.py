"""Assessment orchestration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cisco_collab_health.collectors.base import CollectionContext, Collector
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import AssessmentFacts
from cisco_collab_health.rules.base import HealthRule


@dataclass(frozen=True)
class AssessmentEngine:
    """Runs collectors, applies rules, and returns a structured assessment."""

    collectors: Iterable[Collector]
    rules: Iterable[HealthRule]

    def run(self, context: CollectionContext | None = None) -> AssessmentReport:
        collection_context = context or CollectionContext()
        facts = AssessmentFacts()
        collector_results = []

        for collector in self.collectors:
            result = collector.collect(collection_context)
            collector_results.append(result)
            facts.merge(result.facts)

        findings = []
        for rule in self.rules:
            findings.extend(rule.evaluate(facts))

        return AssessmentReport(
            facts=facts,
            collector_results=collector_results,
            findings=findings,
        )
