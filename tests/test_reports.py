"""Tests for report builders."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cisco_collab_health.collectors.base import CollectionResult, CollectorError
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    DeviceInventoryFact,
    DeviceRegistrationFact,
    PerfCounterFact,
    PlatformCheckFact,
    ServiceStatusFact,
)
from cisco_collab_health.reports.coverage import build_report_coverage
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
        self.assertIn("Devices inventoried: 3", payload)
        self.assertIn("Registrations collected: 5", payload)
        self.assertIn("Services collected: 3", payload)
        self.assertIn("Perf counters collected: 2", payload)
        self.assertIn("Platform checks collected: 2", payload)
        self.assertIn("Collector notes: 1", payload)
        self.assertIn("Collector evidence refs: 1", payload)
        self.assertIn("HTML report: reports/example.html", payload)

    def test_html_report_contains_findings(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn("<!doctype html>", payload)
        self.assertIn("AletheiaUC Assessment", payload)
        self.assertIn("Cluster identity collected", payload)
        self.assertIn("Source: normalized_facts", payload)
        self.assertIn("Collection Coverage", payload)
        self.assertIn("Device Inventory By Model", payload)
        self.assertIn("Device Registration Summary", payload)
        self.assertIn("Device Registration", payload)
        self.assertIn("Services", payload)
        self.assertIn("Performance Counters", payload)
        self.assertIn("Platform Checks", payload)
        self.assertIn("Collector Notes", payload)
        self.assertIn("Collector Evidence", payload)
        self.assertIn("SEP001122334455", payload)
        self.assertIn("Cisco 7945", payload)
        self.assertIn("Gateways/endpoints", payload)
        self.assertIn("SIP trunks", payload)
        self.assertIn("Cisco CallManager", payload)
        self.assertIn("sample.synthetic", payload)

    def test_html_report_puts_summaries_before_detailed_device_tables(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertLess(
            payload.index("Device Inventory By Model"),
            payload.index("Detailed Device Inventory"),
        )
        self.assertLess(
            payload.index("Device Registration Summary"),
            payload.index("Detailed Device Registration"),
        )
        self.assertLess(
            payload.index("Findings"),
            payload.index("Detailed Device Inventory"),
        )

    def test_html_report_summarizes_device_inventory_by_model_and_protocol(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn(
            "<tr><td>Cisco 8845</td><td>1</td><td>0</td><td>0</td><td>1</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>Cisco 7945</td><td>0</td><td>1</td><td>0</td><td>1</td></tr>",
            payload,
        )

    def test_html_report_summarizes_registration_categories(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn(
            "<tr><td>Phones</td><td>2</td><td>1</td><td>0</td><td>3</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>Gateways/endpoints</td><td>1</td><td>0</td><td>0</td><td>1</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>SIP trunks</td><td>0</td><td>1</td><td>0</td><td>1</td></tr>",
            payload,
        )

    def test_coverage_includes_required_categories(self) -> None:
        coverage = build_report_coverage(self.report)
        by_name = {item.name: item for item in coverage}

        self.assertEqual(
            set(by_name),
            {
                "Cluster identity",
                "Cluster nodes",
                "Device inventory",
                "Device registration",
                "Services",
                "Performance counters",
                "Platform checks",
                "Collector issues",
                "Collector notes",
                "Collector evidence",
                "Findings",
            },
        )
        self.assertEqual(by_name["Cluster identity"].status, "collected")
        self.assertEqual(by_name["Cluster nodes"].status, "collected")
        self.assertEqual(by_name["Device inventory"].status, "collected")
        self.assertEqual(by_name["Device registration"].status, "collected")
        self.assertEqual(by_name["Services"].status, "collected")
        self.assertEqual(by_name["Performance counters"].status, "collected")
        self.assertEqual(by_name["Platform checks"].status, "collected")
        self.assertEqual(by_name["Findings"].status, "collected")

    def test_empty_coverage_marks_unimplemented_categories(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[],
            findings=[],
        )

        by_name = {item.name: item for item in build_report_coverage(report)}

        self.assertEqual(by_name["Device registration"].status, "not_implemented")
        self.assertEqual(by_name["Services"].status, "not_implemented")
        self.assertEqual(by_name["Performance counters"].status, "not_implemented")
        self.assertEqual(by_name["Platform checks"].status, "not_implemented")

    def test_axl_skipped_phone_inventory_note_marks_devices_skipped(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    notes=["AXL phone inventory skipped by default."],
                )
            ],
            findings=[],
        )

        by_name = {item.name: item for item in build_report_coverage(report)}

        self.assertEqual(by_name["Device inventory"].status, "skipped")

    def test_device_facts_win_over_skipped_device_note(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP000000000001",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group="Default",
                        location="HQ",
                        region="Default",
                        configured_load=None,
                        source="fixture",
                    )
                ],
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    notes=["AXL phone inventory skipped by default."],
                )
            ],
            findings=[],
        )

        by_name = {item.name: item for item in build_report_coverage(report)}

        self.assertEqual(by_name["Device inventory"].status, "collected")

    def test_html_report_contains_empty_states(self) -> None:
        payload = HtmlReportBuilder().build(
            AssessmentReport(
                facts=AssessmentFacts(),
                collector_results=[],
                findings=[],
            )
        )

        self.assertIn("No device registration facts collected.", payload)
        self.assertIn("No service status facts collected.", payload)
        self.assertIn("No performance counter facts collected.", payload)
        self.assertIn("No platform check facts collected.", payload)
        self.assertIn("No collector notes recorded.", payload)
        self.assertIn("No collector evidence references recorded.", payload)

    def test_html_report_renders_all_current_fact_categories(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                registrations=[
                    DeviceRegistrationFact(
                        name="CSFBOB",
                        status="registered",
                        registered_node="cucm-sub-01",
                        ip_address="192.0.2.51",
                        model="Cisco Unified Client Services Framework",
                        protocol="SIP",
                        source="fixture",
                    )
                ],
                services=[
                    ServiceStatusFact(
                        node="cucm-pub-01",
                        service_name="Cisco Tftp",
                        activated=True,
                        status="STARTED",
                        uptime_seconds=42,
                        source="fixture",
                    )
                ],
                perf_counters=[
                    PerfCounterFact(
                        node="cucm-pub-01",
                        object_name="Memory",
                        counter_name="% Used",
                        instance=None,
                        value=62.4,
                        sample_count=2,
                        source="fixture",
                    )
                ],
                platform_checks=[
                    PlatformCheckFact(
                        node="cucm-pub-01",
                        check_name="ntp",
                        status="synchronized",
                        details={"peer": "192.0.2.1"},
                        source="fixture",
                    )
                ],
            ),
            collector_results=[],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("CSFBOB", payload)
        self.assertIn("Cisco Tftp", payload)
        self.assertIn("% Used", payload)
        self.assertIn("peer: 192.0.2.1", payload)

    def test_html_report_contains_collector_notes_and_evidence(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[
                CollectionResult(
                    collector_name="sample",
                    facts=AssessmentFacts(),
                    evidence=[
                        EvidenceRef(
                            source="sample.synthetic",
                            operation="sample_fixture",
                            node="cucm-pub-01",
                            artifact_path=Path("artifacts/sample.json"),
                            confidence="low",
                            parser="fixture.parser",
                        )
                    ],
                    notes=["Synthetic fixture note"],
                )
            ],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("Collector Notes", payload)
        self.assertIn("Synthetic fixture note", payload)
        self.assertIn("Collector Evidence", payload)
        self.assertIn("sample_fixture", payload)
        self.assertIn("artifacts/sample.json", payload)

    def test_collector_notes_do_not_appear_under_collector_issues(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[
                CollectionResult(
                    collector_name="sample",
                    facts=AssessmentFacts(),
                    notes=["This is a note, not an issue."],
                )
            ],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("This is a note, not an issue.", payload)
        self.assertNotIn("<h2>Collector Issues</h2>", payload)

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
