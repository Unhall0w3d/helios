"""Tests for the bounded Cisco Unity Connection foundation."""

from __future__ import annotations

import unittest
from pathlib import Path

from cisco_collab_health.collectors.cuc import (
    DIAGNOSTIC_CONFIGURATION_PROBES,
    CucCollector,
    _cupi_configuration_records,
    _cupi_total,
)
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.transport.http import CapturedHttpResponse


class FakeHttpClient:
    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        if "rowsPerPage=" not in endpoint or "pageNumber=1" not in endpoint:
            raise AssertionError("CUC probe must remain bounded")
        return CapturedHttpResponse(200, "OK", '<Users total="42" />', Path("response.txt"))


class ConfigurationHttpClient:
    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        if "/smtpserver/serverconfigs" in endpoint:
            body = """{"SmtpServerConfig":{"domainName":"example.invalid","port":25,
            "allowConnectionsFromUntrustedIpAddresses":false,
            "requireAuthenticationFromUntrustedIpAddresses":true,
            "requireTlsFromUntrustedIpAddresses":true}}"""
        else:
            body = '<Items total="0" />'
        return CapturedHttpResponse(200, "OK", body, Path("response.txt"))


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

        self.assertEqual(len(result.facts.configuration_objects), 17)
        self.assertEqual(len(result.evidence), 17)
        self.assertTrue(
            all(
                int(item.details["requested_rows"]) <= 500
                for item in result.facts.configuration_objects
            )
        )

    def test_configuration_parser_retains_only_allowlisted_smtp_fields(self) -> None:
        probe = next(
            item for item in DIAGNOSTIC_CONFIGURATION_PROBES
            if item.object_type == "CucSmtpConfiguration"
        )
        payload = """{"SmtpServerConfig":{"domainName":"example.invalid","port":25,
        "allowConnectionsFromUntrustedIpAddresses":true,
        "requireAuthenticationFromUntrustedIpAddresses":false,
        "requireTlsFromUntrustedIpAddresses":false,"password":"do-not-retain"}}"""

        records = _cupi_configuration_records(payload, probe)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].details["domain"], "example.invalid")
        self.assertEqual(records[0].details["require_tls_untrusted"], "False")
        self.assertNotIn("password", records[0].details)

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

    def test_sanitized_cuc_configuration_is_exposed_and_customer_safe_details_are_hidden(self) -> None:
        result = CucCollector(
            http_client=ConfigurationHttpClient(), diagnostic_capture=True
        ).collect(CollectionContext(product="cuc", publisher_ip="192.0.2.20"))
        report = AssessmentReport(result.facts, [result], [])

        engineering = HtmlReportBuilder().build(report)
        customer_safe = HtmlReportBuilder(customer_safe=True).build(report)

        self.assertIn("Unity Connection Configuration", engineering)
        self.assertIn("example.invalid", engineering)
        self.assertIn("SmtpConfiguration", engineering)
        self.assertNotIn("example.invalid", customer_safe)
        self.assertIn("Configuration names and details omitted", customer_safe)
