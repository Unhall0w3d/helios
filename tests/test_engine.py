"""Tests for assessment orchestration."""

from __future__ import annotations

import unittest

from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.rules.basic import (
    ClusterIdentityRule,
    CollectorHealthRule,
    NodeReachabilityRule,
)


class BrokenCollector:
    name = "broken"

    def collect(self, context: CollectionContext):
        del context
        raise RuntimeError("simulated collector failure")


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

    def test_collector_exception_becomes_structured_error(self) -> None:
        engine = AssessmentEngine(
            collectors=[BrokenCollector(), SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        )

        report = engine.run()

        self.assertEqual(len(report.collector_results), 2)
        self.assertEqual(report.collector_results[0].collector_name, "broken")
        self.assertEqual(len(report.collector_results[0].errors), 1)
        self.assertEqual(report.collector_results[0].errors[0].exception_type, "RuntimeError")
        self.assertEqual(
            report.collector_results[0].errors[0].message,
            "simulated collector failure",
        )
        self.assertEqual(len(report.facts.collector_issues), 1)
        self.assertEqual(report.facts.collector_issues[0].issue_type, "error")
        self.assertEqual(report.facts.cluster.name, "alpha-lab")

    def test_collector_health_rule_reports_collector_errors(self) -> None:
        engine = AssessmentEngine(
            collectors=[BrokenCollector(), SampleCollector()],
            rules=[CollectorHealthRule()],
        )

        report = engine.run()

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].rule_id, "core.collector_health")
        self.assertIn("broken: error", report.findings[0].facts[0])


if __name__ == "__main__":
    unittest.main()
