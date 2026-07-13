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
from cisco_collab_health.models.facts import AssessmentFacts, ConfigurationObjectFact
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.transport.http import CapturedHttpError, CapturedHttpResponse


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


class MailboxStoreFallbackHttpClient:
    def __init__(self):
        self.endpoints = []

    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        self.endpoints.append(endpoint)
        if "/vmrest/mailboxstores" in endpoint:
            raise CapturedHttpError("HTTP 404: Not Found", status=404)
        if "/vmrest/voicemailboxstores" in endpoint:
            return CapturedHttpResponse(
                200,
                "OK",
                '{"@total":"1","MailboxStore":{"DisplayName":"Unity Messaging Database",'
                '"Server":"cuc-pub","Mounted":true,"MaxSizeMB":15000}}',
                Path("response.txt"),
            )
        return CapturedHttpResponse(200, "OK", '<Items total="0" />', Path("response.txt"))


class LiveShapeHttpClient:
    def get(self, endpoint, context, **kwargs):
        del context, kwargs
        if "/messageagingpolicies/" in endpoint and "/messageagingrules" in endpoint:
            body = """<MessageAgingRules total="1"><MessageAgingRule>
            <RuleDescription>Delete expired messages</RuleDescription><Days>30</Days>
            <Enabled>true</Enabled><Action>Delete</Action><AgingRuleType>Deleted</AgingRuleType>
            </MessageAgingRule></MessageAgingRules>"""
        elif "/messageagingpolicies?" in endpoint:
            body = """<MessageAgingPolicies total="1"><MessageAgingPolicy>
            <DisplayName>Default Policy</DisplayName><ObjectId>POLICY-1</ObjectId>
            <Enabled>true</Enabled><MessageAgingRuleURI>/vmrest/messageagingpolicies/POLICY-1/messageagingrules</MessageAgingRuleURI>
            </MessageAgingPolicy></MessageAgingPolicies>"""
        elif "/ports?" in endpoint:
            body = """<Ports total="1"><Port><DisplayName>Port 1</DisplayName>
            <CapEnabled>true</CapEnabled><CapAnswer>true</CapAnswer><CapMWI>true</CapMWI>
            <MediaPortGroupDisplayName>PG-1</MediaPortGroupDisplayName>
            <VmsServerName>cuc-pub</VmsServerName></Port></Ports>"""
        elif "/routingrules?" in endpoint:
            body = """<RoutingRules total="1"><RoutingRule><DisplayName>Forwarded Calls</DisplayName>
            <State>0</State><RuleIndex>1</RuleIndex><Type>Forwarded</Type>
            <RouteAction>Route</RouteAction><RouteTargetHandlerDisplayName>Operator</RouteTargetHandlerDisplayName>
            </RoutingRule></RoutingRules>"""
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
            item
            for item in DIAGNOSTIC_CONFIGURATION_PROBES
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

    def test_mailbox_store_uses_canonical_endpoint_with_legacy_404_fallback(self) -> None:
        client = MailboxStoreFallbackHttpClient()

        result = CucCollector(http_client=client, diagnostic_capture=True).collect(
            CollectionContext(product="cuc", publisher_ip="192.0.2.20")
        )

        self.assertTrue(any("/vmrest/mailboxstores?" in value for value in client.endpoints))
        self.assertTrue(any("/vmrest/voicemailboxstores?" in value for value in client.endpoints))
        mailbox = next(
            item
            for item in result.facts.configuration_objects
            if item.object_type == "CucMailboxStore"
        )
        self.assertEqual(mailbox.name, "Unity Messaging Database")
        self.assertEqual(mailbox.details["server"], "cuc-pub")
        self.assertFalse(any("mailbox stores GET failed" in item for item in result.warnings))

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

    def test_sanitized_cuc_configuration_is_exposed_in_both_report_editions(self) -> None:
        result = CucCollector(
            http_client=ConfigurationHttpClient(), diagnostic_capture=True
        ).collect(CollectionContext(product="cuc", publisher_ip="192.0.2.20"))
        report = AssessmentReport(result.facts, [result], [])

        engineering = HtmlReportBuilder().build(report)
        customer_safe = HtmlReportBuilder(customer_safe=True).build(report)

        self.assertIn("Unity Connection Configuration", engineering)
        self.assertIn("example.invalid", engineering)
        self.assertIn("SmtpConfiguration", engineering)
        self.assertIn("example.invalid", customer_safe)
        self.assertIn("SmtpConfiguration", customer_safe)

    def test_repeated_cuc_schedules_are_aggregated_in_report_details(self) -> None:
        schedule = ConfigurationObjectFact(
            object_type="CucSchedule",
            name="All Hours",
            details={},
            source="CUC.CUPI/vmrest/schedules",
        )
        report = AssessmentReport(
            AssessmentFacts(configuration_objects=[schedule, schedule, schedule]),
            [],
            [],
        )

        html = HtmlReportBuilder().build(report)
        section = html.split("Unity Connection Configuration", 1)[1].split(
            "Collection Coverage",
            1,
        )[0]

        self.assertEqual(section.count(">All Hours<"), 1)
        self.assertIn("<td>3</td>", section)

    def test_live_cupi_aliases_and_message_aging_rules_are_reported(self) -> None:
        result = CucCollector(http_client=LiveShapeHttpClient(), diagnostic_capture=True).collect(
            CollectionContext(product="cuc", publisher_ip="192.0.2.20")
        )

        port = next(
            item for item in result.facts.configuration_objects if item.object_type == "CucPort"
        )
        routing = next(
            item
            for item in result.facts.configuration_objects
            if item.object_type == "CucRoutingRule"
        )
        aging = next(
            item
            for item in result.facts.configuration_objects
            if item.object_type == "CucMessageAgingRule"
        )
        self.assertEqual(port.details["port_group"], "PG-1")
        self.assertEqual(port.details["answer_calls"], "true")
        self.assertEqual(routing.details["state"], "0")
        self.assertNotIn("enabled", routing.details)
        self.assertEqual(aging.details["policy"], "Default Policy")
        self.assertEqual(aging.details["days"], "30")

    def test_inventory_report_marks_bounded_partial_configuration(self) -> None:
        result = CucCollector(http_client=LiveShapeHttpClient(), diagnostic_capture=True).collect(
            CollectionContext(product="cuc", publisher_ip="192.0.2.20")
        )
        html = HtmlReportBuilder().build(AssessmentReport(result.facts, [result], []))

        self.assertIn("Coverage", html)
        self.assertIn("1 of 1 (complete)", html)
