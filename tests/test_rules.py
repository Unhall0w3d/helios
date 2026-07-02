"""Tests for health rules."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.facts import AssessmentFacts, CollaborationNode
from cisco_collab_health.models.findings import FindingSeverity
from cisco_collab_health.rules.basic import NodeReachabilityRule


class NodeReachabilityRuleTests(unittest.TestCase):
    def test_unreachable_node_is_critical(self) -> None:
        facts = AssessmentFacts(
            nodes=[
                CollaborationNode(
                    name="cucm-sub-02",
                    address="192.0.2.12",
                    role="subscriber",
                    reachable=False,
                )
            ]
        )

        findings = NodeReachabilityRule().evaluate(facts)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, FindingSeverity.CRITICAL)
        self.assertIn("cucm-sub-02", findings[0].facts[0])


if __name__ == "__main__":
    unittest.main()
