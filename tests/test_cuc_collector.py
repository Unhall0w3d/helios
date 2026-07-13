"""Tests for the bounded Cisco Unity Connection foundation."""

from __future__ import annotations

import unittest
from pathlib import Path

from cisco_collab_health.collectors.cuc import CucCollector, _cupi_total
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.transport.http import CapturedHttpResponse


class FakeHttpClient:
    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        if "rowsPerPage=1" not in endpoint:
            raise AssertionError("CUC probe must remain bounded")
        return CapturedHttpResponse(200, "OK", '<Users total="42" />', Path("response.txt"))


class CucCollectorTests(unittest.TestCase):
    def test_total_parser_supports_xml_and_json(self) -> None:
        self.assertEqual(_cupi_total('<Users total="42" />'), 42)
        self.assertEqual(_cupi_total('{"total": 7}'), 7)

    def test_collector_captures_bounded_mailbox_inventory(self) -> None:
        result = CucCollector(http_client=FakeHttpClient()).collect(
            CollectionContext(
                product="cuc",
                publisher_ip="192.0.2.20",
                gui_username="admin",
                gui_password="secret",
            )
        )

        self.assertEqual(result.facts.cluster.product, "Cisco Unity Connection")
        self.assertEqual(result.facts.configuration_objects[0].details["total"], "42")
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(result.facts.configuration_objects[1].name, "Unified messaging services")

    def test_diagnostic_capture_collects_bounded_cupi_inventory_counts(self) -> None:
        result = CucCollector(http_client=FakeHttpClient(), diagnostic_capture=True).collect(
            CollectionContext(product="cuc", publisher_ip="192.0.2.20")
        )

        self.assertEqual(len(result.facts.configuration_objects), 7)
        self.assertEqual(len(result.evidence), 7)
        self.assertTrue(
            all(
                item.details["requested_rows"] == "1" for item in result.facts.configuration_objects
            )
        )

    def test_cupi_inventory_is_visible_as_cuc_report_content(self) -> None:
        result = CucCollector(http_client=FakeHttpClient(), diagnostic_capture=True).collect(
            CollectionContext(product="cuc", publisher_ip="192.0.2.20")
        )
        report = AssessmentReport(result.facts, [result], [])

        html = HtmlReportBuilder().build(report)
        coverage = build_report_coverage(report)

        self.assertIn("Unity Connection Inventory", html)
        self.assertIn("Mailboxes", html)
        self.assertIn("Unified messaging services", html)
        self.assertIn("Bounded CUPI inventory counts", html)
        self.assertTrue(
            any(
                item.name == "Unity Connection inventory" and item.status == "collected"
                for item in coverage
            )
        )
