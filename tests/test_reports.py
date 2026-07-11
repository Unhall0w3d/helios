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
    ClusterIdentity,
    DeviceInventoryFact,
    DeviceLoadDefaultFact,
    DeviceRegistrationFact,
    PerfCounterFact,
    PlatformCheckFact,
    ServiceStatusFact,
)
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.formatting import (
    display_bool,
    display_duration,
    display_source,
    display_status_label,
    display_text,
)
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.reconciliation import (
    build_inventory_runtime_reconciliation,
)
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


class ReportBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = AssessmentEngine(
            collectors=[SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        ).run()

    def test_human_readable_report_formatters(self) -> None:
        self.assertEqual(display_duration(42), "Less than 1 minute")
        self.assertEqual(display_duration(31_626_060), "1 year, 1 day, 1 hour, 1 minute")
        self.assertEqual(
            display_source("ControlCenter.soapGetServiceStatus"),
            "Control Center – Service status",
        )
        self.assertEqual(
            display_source("AXL.listPhone.summary, AXL.listDevicePool"),
            "AXL – Phone inventory; AXL – Device pool",
        )

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
        self.assertIn("Device load defaults collected: 3", payload)
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
        self.assertIn("Assessment Methodology and Scope", payload)
        self.assertIn("synthetic sample data", payload)
        self.assertIn("SampleCollector synthetic fixture data", payload)
        self.assertIn("Cluster identity collected", payload)
        self.assertIn("Source: Normalized assessment data", payload)
        self.assertIn("Collection Coverage", payload)
        self.assertIn("Device Inventory By Model", payload)
        self.assertIn("Device Load Summary", payload)
        self.assertIn("Device Registration Summary", payload)
        self.assertIn("Device Registration", payload)
        self.assertIn("Services", payload)
        self.assertIn("Performance Counters", payload)
        self.assertIn("Platform Checks", payload)
        self.assertIn("Collector Notes", payload)
        self.assertIn("Collector Evidence", payload)
        self.assertIn("Inventory / Runtime Reconciliation", payload)
        self.assertIn("SEP001122334455", payload)
        self.assertIn("Cisco 7945", payload)
        self.assertIn("SCCP45.9-4-2SR4-3", payload)
        self.assertIn("Gateways/endpoints", payload)
        self.assertIn("SIP trunks", payload)
        self.assertIn("Cisco CallManager", payload)
        self.assertIn("Sample data", payload)
        self.assertIn("Call Manager Group", payload)
        self.assertIn("Region", payload)

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

    def test_html_report_summarizes_device_loads(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn(
            (
                "<tr><td>Cisco 8845</td><td>SIP</td><td>sip8845.14-2-1</td>"
                "<td>1</td><td>0</td><td>0</td><td>0</td></tr>"
            ),
            payload,
        )
        self.assertIn(
            (
                "<tr><td>Cisco Unified Client Services Framework</td><td>SIP</td><td>—</td>"
                "<td>1</td><td>0</td><td>1</td><td>0</td></tr>"
            ),
            payload,
        )

    def test_html_report_marks_load_comparison_unavailable_without_defaults(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP000000000001",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location="HQ",
                        region=None,
                        configured_load=None,
                        source="fixture",
                    )
                ]
            ),
            collector_results=[],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("Device load defaults were unavailable", payload)
        self.assertNotIn("Unknown Default</th><td>1", payload)

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
                "Device load defaults",
                "Configuration inventory",
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
        self.assertEqual(by_name["Device load defaults"].status, "collected")
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
        self.assertEqual(by_name["Device load defaults"].status, "not_collected")
        self.assertEqual(by_name["Services"].status, "not_implemented")
        self.assertEqual(by_name["Performance counters"].status, "not_implemented")
        self.assertEqual(by_name["Platform checks"].status, "not_implemented")

    def test_display_formatters_render_report_friendly_values(self) -> None:
        self.assertEqual(display_text(None), "—")
        self.assertEqual(display_text("  "), "—")
        self.assertEqual(display_text(42), "42")
        self.assertEqual(display_bool(True), "Yes")
        self.assertEqual(display_bool(False), "No")
        self.assertEqual(display_bool(None), "—")
        self.assertEqual(display_status_label("not_implemented"), "Not implemented")

    def test_html_report_renders_friendly_statuses_and_empty_values(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn("<td>Collected</td>", payload)
        self.assertIn("<td>Yes</td>", payload)
        self.assertIn("<td>—</td>", payload)
        self.assertNotIn("<td>True</td>", payload)
        self.assertNotIn("<td>not_implemented</td>", payload)

    def test_html_report_includes_axl_source_captions_when_evidence_exists(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                cluster=ClusterIdentity(
                    name="prod-cluster",
                    product="Cisco Unified Communications Manager",
                    version="15.0",
                ),
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group="CMG-PubSub",
                        location=None,
                        region="Region-HQ",
                        configured_load=None,
                        source="AXL.listPhone.summary, AXL.listDevicePool",
                    )
                ],
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    evidence=[
                        EvidenceRef(
                            source="AXL",
                            operation="listPhone",
                            confidence="medium",
                        )
                    ],
                )
            ],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("Source: AXL getCCMVersion and listProcessNode.", payload)
        self.assertIn(
            "Source: AXL listPhone summary inventory enriched by AXL listDevicePool.",
            payload,
        )
        self.assertIn("Source: RISPort70 SelectCmDeviceExt", payload)

    def test_html_report_renders_enriched_device_inventory_fields(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description=None,
                        model="Cisco 8845",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group="CMG-PubSub",
                        location="HQ-Loc",
                        region="Region-HQ",
                        configured_load="sip8845.14-2-1",
                        source="AXL.listPhone.summary, AXL.listDevicePool",
                    )
                ]
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    evidence=[
                        EvidenceRef(source="AXL", operation="listPhone", confidence="medium"),
                        EvidenceRef(source="AXL", operation="listDevicePool", confidence="medium"),
                    ],
                )
            ],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("CMG-PubSub", payload)
        self.assertIn("Region-HQ", payload)

    def test_inventory_runtime_reconciliation_matches_by_device_name(self) -> None:
        reconciliation = build_inventory_runtime_reconciliation(
            devices=[
                DeviceInventoryFact(
                    name="SEP001122334455",
                    description=None,
                    model="Cisco 8845",
                    protocol="SIP",
                    device_pool="Default",
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="fixture",
                ),
                DeviceInventoryFact(
                    name="CSFALICE",
                    description=None,
                    model="Cisco Unified Client Services Framework",
                    protocol="SIP",
                    device_pool="Softphone",
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="fixture",
                ),
            ],
            registrations=[
                DeviceRegistrationFact(
                    name="sep001122334455",
                    status="registered",
                    registered_node="cucm-pub-01",
                    ip_address="192.0.2.50",
                    model="Cisco 8845",
                    protocol="SIP",
                    source="fixture",
                ),
                DeviceRegistrationFact(
                    name="HQ-VG01",
                    status="registered",
                    registered_node="cucm-pub-01",
                    ip_address="192.0.2.60",
                    model="Cisco VG Gateway",
                    protocol="MGCP",
                    source="fixture",
                ),
            ],
        )

        self.assertEqual(reconciliation.matched_names, ["sep001122334455"])
        self.assertEqual([device.name for device in reconciliation.inventory_only], ["CSFALICE"])
        self.assertEqual(
            [registration.name for registration in reconciliation.runtime_only],
            ["HQ-VG01"],
        )

    def test_html_reconciliation_section_is_informational_only(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn("Runtime-only Devices", payload)
        self.assertIn("HQ-VG01", payload)
        self.assertIn("ITSP-SIP-TRUNK", payload)
        self.assertIn("Differences are not health findings.", payload)
        self.assertIn("not automatically unregistered or unhealthy", payload)
        self.assertNotIn("inventory.runtime_reconciliation", payload)

    def test_axl_skipped_phone_inventory_note_marks_devices_skipped(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    status_flags=[
                        "axl.phone_inventory.skipped",
                    ],
                )
            ],
            findings=[],
        )

        by_name = {item.name: item for item in build_report_coverage(report)}

        self.assertEqual(by_name["Device inventory"].status, "skipped")
        self.assertEqual(by_name["Device load defaults"].status, "skipped")

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
                device_load_defaults=[
                    DeviceLoadDefaultFact(
                        model="Cisco 8845",
                        protocol="SIP",
                        default_load="sip8845.14-2-1",
                        source="fixture",
                    )
                ],
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    status_flags=[
                        "axl.phone_inventory.skipped",
                    ],
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
        self.assertIn("No device inventory facts collected.", payload)
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
