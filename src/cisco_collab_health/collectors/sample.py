"""Offline sample collector for alpha testing."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, ClusterIdentity, CollaborationNode


class SampleCollector:
    """Returns deterministic facts without connecting to external systems."""

    name = "sample"

    def collect(self, context: CollectionContext) -> CollectionResult:
        del context
        return CollectionResult(
            collector_name=self.name,
            facts=AssessmentFacts(
                cluster=ClusterIdentity(
                    name="alpha-lab",
                    product="Cisco Unified Communications Manager",
                    version="14.0",
                ),
                nodes=[
                    CollaborationNode(
                        name="cucm-pub-01",
                        address="192.0.2.10",
                        role="publisher",
                        reachable=True,
                    ),
                    CollaborationNode(
                        name="cucm-sub-01",
                        address="192.0.2.11",
                        role="subscriber",
                        reachable=True,
                    ),
                ],
            ),
        )
