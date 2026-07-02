"""Tests for report builders."""

from __future__ import annotations

import json
import unittest

from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.markdown import MarkdownReportBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


class ReportBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = AssessmentEngine(
            collectors=[SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        ).run()

    def test_json_report_is_parseable(self) -> None:
        payload = JsonReportBuilder().build(self.report)

        parsed = json.loads(payload)

        self.assertEqual(parsed["facts"]["cluster"]["name"], "alpha-lab")
        self.assertEqual(parsed["findings"][0]["severity"], "info")

    def test_markdown_report_contains_findings(self) -> None:
        payload = MarkdownReportBuilder().build(self.report)

        self.assertIn("# Cisco Collaboration Health Assessment", payload)
        self.assertIn("## Findings", payload)
        self.assertIn("Cluster identity collected", payload)


if __name__ == "__main__":
    unittest.main()
