"""Tests for report builders."""

from __future__ import annotations

import json
import unittest

from cisco_collab_health.collectors.base import CollectionResult, CollectorError
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import AssessmentFacts
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
        self.assertEqual(parsed["findings"][0]["evidence"][0]["source"], "normalized_facts")
        self.assertIn("collected_at", parsed["findings"][0]["evidence"][0])

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
        self.assertIn("Source: normalized_facts", payload)

    def test_html_report_contains_collector_issues(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    warnings=["AXL getCCMVersion failed: HTTP 599"],
                    errors=[
                        CollectorError(
                            message="simulated collector failure",
                            exception_type="RuntimeError",
                        )
                    ],
                )
            ],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("Collector Issues", payload)
        self.assertIn("AXL getCCMVersion failed: HTTP 599", payload)
        self.assertIn("RuntimeError: simulated collector failure", payload)


if __name__ == "__main__":
    unittest.main()
