"""Tests for report builders."""

from __future__ import annotations

import json
import unittest

from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
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

    def test_executive_summary_contains_overview(self) -> None:
        payload = ExecutiveSummaryBuilder().build(self.report, "reports/example.html")

        self.assertIn("Executive Summary", payload)
        self.assertIn("Nodes discovered: 2", payload)
        self.assertIn("HTML report: reports/example.html", payload)

    def test_html_report_contains_findings(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn("<!doctype html>", payload)
        self.assertIn("Cisco Collaboration Health Assessment", payload)
        self.assertIn("Cluster identity collected", payload)


if __name__ == "__main__":
    unittest.main()
