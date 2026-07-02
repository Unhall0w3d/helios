"""Tests for assessment orchestration."""

from __future__ import annotations

import unittest

from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


class AssessmentEngineTests(unittest.TestCase):
    def test_sample_assessment_runs_end_to_end(self) -> None:
        engine = AssessmentEngine(
            collectors=[SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        )

        report = engine.run()

        self.assertIsNotNone(report.facts.cluster)
        self.assertEqual(len(report.facts.nodes), 2)
        self.assertEqual(len(report.collector_results), 1)
        self.assertEqual(
            [finding.rule_id for finding in report.findings],
            ["core.cluster_identity", "core.node_reachability"],
        )


if __name__ == "__main__":
    unittest.main()
