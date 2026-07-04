"""Initial conservative health rules for alpha testing."""

from __future__ import annotations

from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import AssessmentFacts
from cisco_collab_health.models.findings import (
    FindingSeverity,
    HealthFinding,
    RecommendationKind,
)


class ClusterIdentityRule:
    """Checks whether a cluster identity was collected."""

    rule_id = "core.cluster_identity"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if facts.cluster is not None:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="Cluster identity collected",
                    severity=FindingSeverity.INFO,
                    recommendation_kind=RecommendationKind.INFORMATIONAL,
                    facts=[
                        f"Product: {facts.cluster.product}",
                        f"Version: {facts.cluster.version}",
                        f"Cluster name: {facts.cluster.name}",
                    ],
                    reasoning="The assessment has enough identity data to anchor later findings.",
                    evidence=[
                        EvidenceRef(
                            source="normalized_facts",
                            operation="cluster_identity",
                        )
                    ],
                )
            ]

        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="Cluster identity was not collected",
                severity=FindingSeverity.WARNING,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=["No normalized cluster identity facts were produced by collectors."],
                reasoning=(
                    "Most health findings need product and version context before they can be "
                    "interpreted accurately."
                ),
                recommendation="Verify that at least one identity-capable collector is configured.",
            )
        ]


class NodeReachabilityRule:
    """Reports nodes with explicit unreachable status."""

    rule_id = "core.node_reachability"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.nodes:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="No collaboration nodes were collected",
                    severity=FindingSeverity.WARNING,
                    recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                    facts=["No normalized node facts were produced by collectors."],
                    reasoning=(
                        "Cluster health cannot be evaluated until the Publisher API or another "
                        "authoritative source returns cluster node inventory."
                    ),
                    recommendation=(
                        "Verify API reachability and collector warnings for cluster discovery."
                    ),
                )
            ]

        unreachable_nodes = [node for node in facts.nodes if node.reachable is False]
        if not unreachable_nodes:
            return [
                HealthFinding(
                    rule_id=self.rule_id,
                    title="No unreachable nodes reported",
                    severity=FindingSeverity.INFO,
                    recommendation_kind=RecommendationKind.INFORMATIONAL,
                    facts=[f"Nodes evaluated: {len(facts.nodes)}"],
                    reasoning=(
                        "No collector reported an explicit unreachable status for any "
                        "normalized node."
                    ),
                )
            ]

        node_names = ", ".join(node.name for node in unreachable_nodes)
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more nodes were reported unreachable",
                severity=FindingSeverity.CRITICAL,
                recommendation_kind=RecommendationKind.REQUIREMENT,
                facts=[f"Unreachable nodes: {node_names}"],
                reasoning=(
                    "Unreachable collaboration nodes can indicate service disruption, "
                    "network issues, "
                    "or collection credential problems that require investigation."
                ),
                recommendation=(
                    "Validate node reachability and distinguish service impact from "
                    "collection failure."
                ),
                evidence=[
                    EvidenceRef(
                        source="normalized_facts",
                        operation="node_reachability",
                        node=node.name,
                    )
                    for node in unreachable_nodes
                ],
            )
        ]


class CollectorHealthRule:
    """Reports collector warnings and errors as assessment findings."""

    rule_id = "core.collector_health"

    def evaluate(self, facts: AssessmentFacts) -> list[HealthFinding]:
        if not facts.collector_issues:
            return []

        has_error = any(issue.issue_type == "error" for issue in facts.collector_issues)
        severity = FindingSeverity.CRITICAL if has_error else FindingSeverity.WARNING
        return [
            HealthFinding(
                rule_id=self.rule_id,
                title="One or more collectors reported issues",
                severity=severity,
                recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
                facts=[
                    f"{issue.collector_name}: {issue.issue_type}: {issue.message}"
                    for issue in facts.collector_issues
                ],
                reasoning=(
                    "Collector warnings or failures can make the assessment incomplete or reduce "
                    "confidence in related findings."
                ),
                recommendation=(
                    "Review collector warnings/errors and raw artifacts before relying on the "
                    "assessment."
                ),
                evidence=[
                    EvidenceRef(
                        source=issue.source,
                        operation="collector_health",
                        confidence="high",
                    )
                    for issue in facts.collector_issues
                ],
            )
        ]
