"""Assessment orchestration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cisco_collab_health.collectors.base import (
    CollectionContext,
    CollectionResult,
    Collector,
    CollectorError,
)
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import AssessmentFacts, CollectorIssueFact
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
            try:
                result = collector.collect(collection_context)
            except Exception as exc:
                result = CollectionResult(
                    collector_name=getattr(collector, "name", collector.__class__.__name__),
                    facts=AssessmentFacts(),
                    errors=[
                        CollectorError(
                            message=str(exc),
                            exception_type=exc.__class__.__name__,
                        )
                    ],
                )
            collector_results.append(result)
            facts.merge(result.facts)
            for warning in result.warnings:
                facts.collector_issues.append(
                    CollectorIssueFact(
                        collector_name=result.collector_name,
                        issue_type="warning",
                        message=warning,
                    )
                )
            for error in result.errors:
                facts.collector_issues.append(
                    CollectorIssueFact(
                        collector_name=result.collector_name,
                        issue_type="error",
                        message=error.message,
                        exception_type=error.exception_type,
                    )
                )

        findings = []
        for rule in self.rules:
            findings.extend(rule.evaluate(facts))

        return AssessmentReport(
            facts=facts,
            collector_results=collector_results,
            findings=findings,
        )
