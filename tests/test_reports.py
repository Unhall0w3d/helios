"""Tests for report builders."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cisco_collab_health.collectors.base import CollectionResult, CollectorError
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.findings import (
    FindingSeverity,
    HealthFinding,
    RecommendationKind,
)
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    CollaborationNode,
    ConfigurationObjectFact,
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
from cisco_collab_health.reports.html import (
    REPORT_THEMES,
    HtmlReportBuilder,
    _theme_asset_data_uri,
    available_report_templates,
)
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.reconciliation import (
    build_inventory_runtime_reconciliation,
    runtime_resource_category,
)
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


class ReportBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = AssessmentEngine(
            collectors=[SampleCollector()],
            rules=[ClusterIdentityRule(), NodeReachabilityRule()],
        ).run()

    @staticmethod
    def _write_external_template(root: Path, *, key: str = "privatebrand") -> Path:
        package = root / key
        assets = package / "assets"
        assets.mkdir(parents=True)
        (assets / "logo.svg").write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"></svg>',
            encoding="utf-8",
        )
        (package / "theme.css").write_text(
            f"body.{key}-report {{ color: #123456; }}",
            encoding="utf-8",
        )
        manifest = {
            "schema_version": 1,
            "key": key,
            "template": {
                "title": "Private Brand Assessment",
                "eyebrow": "Authorized report",
                "tagline": "Private presentation pack",
                "footer_label": "Prepared by Private Brand",
            },
            "theme": {
                "stylesheet": "theme.css",
                "asset_directory": "assets",
                "slots": {"logo-primary": "logo.svg"},
                "colors": {
                    "page": "#ffffff",
                    "surface": "#ffffff",
                    "text": "#111111",
                    "muted": "#555555",
                    "accent": "#123456",
                    "cyan": "#0088aa",
                    "gold": "#aa8800",
                },
                "hero_overlay": "none",
                "hero_focal_point": "center",
                "watermark_opacity": "0",
                "show_hero_logo": True,
                "show_footer_logo": True,
            },
        }
        (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return package

    def test_human_readable_report_formatters(self) -> None:
        self.assertEqual(display_duration(42), "Less than 1 minute")
        self.assertEqual(display_duration(31_626_060), "1 year, 1 day, 1 hour, 1 minute")
        self.assertEqual(
            display_source("ControlCenter.soapGetServiceStatus"),
            "Control Center – Service status",
        )

    def test_themes_share_design_system_components_and_remain_standalone(self) -> None:
        self.assertIn("aletheiauc", available_report_templates())
        for theme in available_report_templates():
            payload = HtmlReportBuilder(template=theme).build(self.report)
            self.assertIn("rds-report", payload)
            self.assertIn("rds-hero__art", payload)
            self.assertIn("rds-section", payload)
            self.assertIn("rds-transition", payload)
            self.assertIn("rds-executive", payload)
            self.assertEqual(payload.count('class="rds-metric-group"'), 4)
            self.assertEqual(payload.count('class="rds-metric rds-metric--'), 12)
            self.assertIn("rds-chapter--scope", payload)
            self.assertIn("rds-recommendation", payload)
            self.assertIn("rds-footer", payload)
            if theme == "comsource":
                self.assertIn("data:image", payload)
            else:
                self.assertNotIn("data:image", payload)
            self.assertNotIn("https://", payload)

    def test_every_required_theme_asset_slot_resolves_without_remote_dependency(self) -> None:
        for theme in available_report_templates():
            package = REPORT_THEMES[theme]
            for slot in package.slots:
                asset = _theme_asset_data_uri(theme, slot)
                self.assertTrue(asset.startswith("data:image/"))
                self.assertNotIn("https://", asset)

    def test_multi_target_scope_is_visible_in_html_and_summary(self) -> None:
        report = AssessmentReport(
            facts=self.report.facts,
            collector_results=self.report.collector_results,
            findings=self.report.findings,
            runtime_metadata={
                "targets": [
                    {
                        "target_id": "call-control",
                        "technology": "cucm",
                        "address": "192.0.2.10",
                        "connection_profile": "cucm-lab",
                    },
                    {
                        "target_id": "voicemail",
                        "technology": "cuc",
                        "address": "192.0.2.20",
                        "connection_profile": "cuc-lab",
                    },
                ]
            },
        )

        html = HtmlReportBuilder().build(report)
        summary = ExecutiveSummaryBuilder().build(report)

        self.assertIn("Assessment Targets", html)
        self.assertIn("voicemail", html)
        self.assertIn('<span class="meta-chip scope">CUCM Cluster</span>', html)
        self.assertIn('<span class="meta-chip scope">CUC Cluster</span>', html)
        self.assertNotIn("CER Cluster", html)
        self.assertNotIn("IM&amp;P Cluster", html)
        self.assertIn("Assessment targets: 2", summary)
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
        self.assertIn("Collaboration Health Assessment", payload)
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

    def test_default_template_is_generic_dark_and_text_first_in_both_editions(self) -> None:
        engineering = HtmlReportBuilder().build(self.report)
        customer = HtmlReportBuilder(customer_safe=True).build(self.report)

        for payload in (engineering, customer):
            self.assertIn("Collaboration Health Assessment", payload)
            self.assertIn("Evidence-led review and actionable findings", payload)
            self.assertIn('class="default-dark-report"', payload)
            self.assertIn("capability-row", payload)
            self.assertIn("report-shell", payload)
            self.assertIn("report-hero", payload)
            self.assertNotIn('class="hero-art rds-hero__art"', payload)
            self.assertNotIn("data:image", payload)
            self.assertNotIn("AletheiaUC", payload)
            self.assertIn("body.default-dark-report", payload)
            self.assertNotIn("https://", payload)
        self.assertIn("Engineering edition", engineering)
        self.assertIn("Customer deliverable", customer)
        self.assertIn(".header-meta", engineering)
        self.assertIn("justify-content: center", engineering)
        self.assertIn("Engineering health report", engineering)
        self.assertIn("Customer assessment report", customer)
        self.assertNotIn("Engineering health report", customer)

    def test_default_template_uses_shared_design_system_without_artwork(self) -> None:
        payload = HtmlReportBuilder().build(self.report)
        hero_copy = payload.split('<div class="hero-copy rds-hero__content">', 1)[1].split(
            '<div class="capability-row',
            1,
        )[0]

        self.assertIn("rds-hero__overlay", payload)
        self.assertIn("rds-executive", payload)
        self.assertEqual(payload.count('class="rds-metric-group"'), 4)
        self.assertEqual(payload.count('class="rds-metric rds-metric--'), 12)
        self.assertIn("rds-chapter--findings", payload)
        self.assertIn("rds-chapter--evidence", payload)
        self.assertIn("rds-recommendation", payload)
        self.assertIn("--section-band-image", payload)
        self.assertIn("--executive-image", payload)
        self.assertIn("--footer-image", payload)
        self.assertIn("body.default-dark-report", payload)
        self.assertIn("Collaboration Health Assessment", payload)
        self.assertNotIn("data:image", payload)
        self.assertNotIn('class="rds-logo"', hero_copy)
        footer = payload.split('<footer class="template-footer rds-footer"', 1)[1]
        self.assertNotIn('class="rds-logo"', footer)
        self.assertIn(".rds-metric-grid", payload)
        self.assertIn("repeat(3, minmax(0, 1fr))", payload)
        self.assertIn("overflow-wrap: anywhere", payload)
        self.assertIn("@media (max-width: 620px)", payload)

    def test_methodology_uses_runtime_metadata_aliases_and_preserves_unknown_scope(self) -> None:
        report = AssessmentReport(
            facts=self.report.facts,
            collector_results=[],
            findings=self.report.findings,
            runtime_metadata={
                "assessment_profile": "Production Assessment",
                "publisher_ip": "192.0.2.10",
            },
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("Production Assessment", payload)
        self.assertIn("192.0.2.10", payload)
        self.assertIn("<th>Phone inventory scope</th><td>Not specified</td>", payload)
        self.assertIn("Source: Read-only SSH/CLI platform diagnostics.", payload)
        self.assertNotIn("Real collector not implemented yet", payload)

    def test_external_template_pack_is_discovered_and_rendered_standalone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self._write_external_template(root)
            with patch.dict(
                os.environ,
                {"ALETHEIAUC_REPORT_TEMPLATE_DIR": str(root)},
            ):
                self.assertIn("privatebrand", available_report_templates())
                payload = HtmlReportBuilder(customer_safe=True, template="privatebrand").build(
                    self.report
                )

        self.assertIn("Private Brand Assessment", payload)
        self.assertIn("Prepared by Private Brand", payload)
        self.assertIn("body.privatebrand-report { color: #123456; }", payload)
        self.assertIn("data:image/svg+xml;base64", payload)
        self.assertNotIn("https://", payload)

    def test_external_template_is_unavailable_when_pack_is_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(
                os.environ,
                {"ALETHEIAUC_REPORT_TEMPLATE_DIR": tmpdir},
            ):
                self.assertEqual(available_report_templates(), ("aletheiauc",))
                with self.assertRaisesRegex(ValueError, "Unknown HTML report template"):
                    HtmlReportBuilder(template="privatebrand")

    def test_customer_deliverable_retains_scope_identifiers_and_evidence_operations(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                nodes=[
                    CollaborationNode("cuc-pub", "192.0.2.20", "publisher", technology="cuc"),
                    CollaborationNode("cuc-sub", "192.0.2.21", "subscriber", technology="cuc"),
                    CollaborationNode("cucm-pub", "192.0.2.10", "publisher", technology="cucm"),
                ]
            ),
            collector_results=self.report.collector_results,
            findings=self.report.findings,
            runtime_metadata={
                "targets": [
                    {"target_id": "Yorktown-Voice", "technology": "cuc", "address": "192.0.2.20"},
                    {
                        "target_id": "Yorktown-Call-Control",
                        "technology": "cucm",
                        "address": "192.0.2.10",
                    },
                ]
            },
        )

        payload = HtmlReportBuilder(customer_safe=True).build(report)

        self.assertIn("Yorktown-Voice", payload)
        self.assertIn("Yorktown-Call-Control", payload)
        self.assertIn("cuc-pub", payload)
        self.assertIn("cucm-pub", payload)
        self.assertIn("Collector Evidence", payload)
        self.assertIn("CUCM configuration discovery; Unity Connection cluster status", payload)

    def test_target_scope_uses_discovered_publisher_when_address_is_unavailable(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                nodes=[
                    CollaborationNode(
                        "cucm-pub.example",
                        "192.0.2.10",
                        "publisher",
                        target_id="voice",
                        technology="cucm",
                    )
                ]
            ),
            collector_results=[],
            findings=[],
            runtime_metadata={
                "targets": [{"target_id": "voice", "technology": "cucm", "address": None}]
            },
        )

        engineering = HtmlReportBuilder().build(report)
        customer = HtmlReportBuilder(customer_safe=True).build(report)
        self.assertIn("Server address", engineering)
        self.assertIn("192.0.2.10", engineering)
        self.assertIn("Server address", customer)
        self.assertIn("192.0.2.10", customer)

    def test_priority_findings_retain_customer_facts_and_evidence_without_artifact_paths(
        self,
    ) -> None:
        finding = HealthFinding(
            rule_id="certificates.expired",
            title="One certificate is expired",
            severity=FindingSeverity.CRITICAL,
            recommendation_kind=RecommendationKind.ENGINEERING_RECOMMENDATION,
            facts=["tomcat certificate on cucm-pub: expired 4 days ago"],
            reasoning="An expired certificate can interrupt secure services and integrations.",
            recommendation="Have the UC administrator renew the certificate and validate services.",
            evidence=[
                EvidenceRef(
                    source="CertificateManagementREST",
                    operation="snapshot_server",
                    node="cucm-pub",
                )
            ],
        )
        observation = HealthFinding(
            rule_id="inventory.summary",
            title="Inventory collected",
            severity=FindingSeverity.INFO,
            recommendation_kind=RecommendationKind.INFORMATIONAL,
            facts=["Phones: 100"],
            reasoning="Inventory was collected.",
        )
        report = AssessmentReport(
            facts=AssessmentFacts(), collector_results=[], findings=[finding, observation]
        )

        engineering = HtmlReportBuilder().build(report)
        customer = HtmlReportBuilder(customer_safe=True).build(report)

        for payload in (engineering, customer):
            self.assertIn("Why it matters:", payload)
            self.assertIn("What we found:", payload)
            self.assertIn("Recommended next step:", payload)
            self.assertIn("Assessment observations (1)", payload)
        self.assertIn("tomcat certificate on cucm-pub: expired 4 days ago", engineering)
        self.assertIn("tomcat certificate on cucm-pub: expired 4 days ago", customer)
        self.assertIn("Technical collection detail", engineering)
        self.assertNotIn("Technical collection detail", customer)

    def test_aletheiauc_header_shows_diagnostic_state(self) -> None:
        report = AssessmentReport(
            facts=self.report.facts,
            collector_results=self.report.collector_results,
            findings=self.report.findings,
            runtime_metadata={"diagnostic_capture": True},
        )

        html = HtmlReportBuilder().build(report)

        self.assertIn("CUCM Cluster", html)
        self.assertIn("Diagnostic capture enabled", html)

    def test_unknown_html_template_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown HTML report template"):
            HtmlReportBuilder(template="not-a-template")

    def test_registered_template_with_missing_assets_has_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            package = self._write_external_template(root)
            (package / "assets" / "logo.svg").unlink()
            with patch.dict(
                os.environ,
                {"ALETHEIAUC_REPORT_TEMPLATE_DIR": str(root)},
            ):
                with self.assertRaisesRegex(ValueError, "not installed locally"):
                    HtmlReportBuilder(template="privatebrand")

    def test_server_rows_put_cucm_before_cuc_and_publishers_before_subscribers(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                clusters=[
                    ClusterIdentity("unity", "Cisco Unity Connection", "15"),
                    ClusterIdentity("call-control", "Cisco Unified Communications Manager", "15"),
                ],
                nodes=[
                    CollaborationNode("cucm-sub10", "192.0.2.20", "subscriber", technology="cucm"),
                    CollaborationNode("cuc-pub", "192.0.2.21", "publisher", technology="cuc"),
                    CollaborationNode("cucm-pub", "192.0.2.11", "publisher", technology="cucm"),
                    CollaborationNode("cuc-sub2", "192.0.2.22", "subscriber", technology="cuc"),
                    CollaborationNode("cucm-sub2", "192.0.2.12", "subscriber", technology="cucm"),
                    CollaborationNode("cuc-sub1", "192.0.2.23", "subscriber", technology="cuc"),
                ],
                services=[
                    ServiceStatusFact("cuc-sub2", "svc", True, "started", 1, "ControlCenter"),
                    ServiceStatusFact("cucm-sub10", "svc", True, "started", 1, "ControlCenter"),
                    ServiceStatusFact("cuc-pub", "svc", True, "started", 1, "ControlCenter"),
                    ServiceStatusFact("cucm-pub", "svc", True, "started", 1, "ControlCenter"),
                    ServiceStatusFact("cucm-sub2", "svc", True, "started", 1, "ControlCenter"),
                ],
                perf_counters=[
                    PerfCounterFact("cuc-pub", "Memory", "% Mem Used", None, 40, 1, "PerfMon"),
                    PerfCounterFact("cucm-sub2", "Memory", "% Mem Used", None, 30, 1, "PerfMon"),
                    PerfCounterFact("cucm-pub", "Memory", "% Mem Used", None, 20, 1, "PerfMon"),
                ],
                platform_checks=[
                    PlatformCheckFact("cuc-sub2", "show status", "ok", {}, "CUC.UCOS.CLI"),
                    PlatformCheckFact("cuc-pub", "show status", "ok", {}, "CUC.UCOS.CLI"),
                    PlatformCheckFact("cucm-sub2", "show status", "ok", {}, "CUCM.UCOS.CLI"),
                    PlatformCheckFact("cucm-pub", "show status", "ok", {}, "CUCM.UCOS.CLI"),
                ],
            ),
            collector_results=[],
            findings=[],
            runtime_metadata={
                "targets": [
                    {"target_id": "unity", "technology": "cuc", "address": "192.0.2.21"},
                    {"target_id": "call-control", "technology": "cucm", "address": "192.0.2.11"},
                ]
            },
        )

        builder = HtmlReportBuilder()
        node_rows = builder._node_rows(report)
        service_rows = builder._service_rows(report)
        perf_rows = builder._perf_counter_rows(report)
        platform_rows = builder._platform_check_rows(report)
        cuc_platform = builder._cuc_platform_section(report)
        cluster_section = builder._cluster_section(report)
        target_section = builder._target_scope_section(report)

        expected = ("cucm-pub", "cucm-sub2", "cucm-sub10", "cuc-pub", "cuc-sub1", "cuc-sub2")
        for first, second in zip(expected, expected[1:]):
            self.assertLess(node_rows.index(first), node_rows.index(second))
        service_expected = ("cucm-pub", "cucm-sub2", "cucm-sub10", "cuc-pub", "cuc-sub2")
        for first, second in zip(service_expected, service_expected[1:]):
            self.assertLess(service_rows.index(first), service_rows.index(second))
        self.assertLess(perf_rows.index("cucm-pub"), perf_rows.index("cucm-sub2"))
        self.assertLess(perf_rows.index("cucm-sub2"), perf_rows.index("cuc-pub"))
        self.assertLess(platform_rows.index("cucm-pub"), platform_rows.index("cucm-sub2"))
        self.assertLess(platform_rows.index("cucm-sub2"), platform_rows.index("cuc-pub"))
        self.assertLess(cuc_platform.index("cuc-pub"), cuc_platform.index("cuc-sub2"))
        self.assertLess(cluster_section.index("call-control"), cluster_section.index("unity"))
        self.assertLess(target_section.index("call-control"), target_section.index("unity"))

    def test_lengthy_report_tables_are_collapsible_and_printable(self) -> None:
        for template in available_report_templates():
            for customer_safe in (False, True):
                html = HtmlReportBuilder(template=template, customer_safe=customer_safe).build(
                    self.report
                )

                for summary in (
                    "Show device inventory by model",
                    "Show device load defaults and overrides",
                    "Show active firmware by model",
                    "Show performance summary",
                    "Show configuration inventory summary",
                    "Show certificates requiring attention",
                    "Show platform checks",
                    "Show collector evidence",
                    "Show configured endpoints without a runtime observation",
                ):
                    self.assertIn(
                        f'<details class="report-data"><summary>{summary}</summary>', html
                    )
                self.assertIn("details.report-data:not([open]) > *:not(summary)", html)
                self.assertIn("details.report-data:not([open]) > table", html)

    def test_node_reachability_is_inferred_from_successful_collection(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                nodes=[
                    CollaborationNode("cucm-pub", "192.0.2.11", "publisher"),
                    CollaborationNode("cucm-sub", "192.0.2.12", "subscriber"),
                ]
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    evidence=[
                        EvidenceRef(source="AXL", operation="getCCMVersion", node="192.0.2.11")
                    ],
                )
            ],
            findings=[],
        )

        html = HtmlReportBuilder().build(report)

        self.assertIn("Yes (data collected)", html)
        self.assertIn("Not assessed directly", html)

    def test_registration_caption_identifies_supplemental_all_class_query(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                registrations=[
                    DeviceRegistrationFact(
                        name="SIPTRUNK-1",
                        status="Registered",
                        registered_node="cucm-pub",
                        ip_address="192.0.2.30",
                        model="SIP Trunk",
                        protocol="SIP",
                        source="RISPort70.selectCmDevice",
                        device_class="SIPTrunk",
                    )
                ]
            ),
            collector_results=[],
            findings=[],
        )

        html = HtmlReportBuilder().build(report)

        self.assertIn("SelectCmDeviceExt phone detail and SelectCmDevice", html)

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
                "<td>1</td><td>1</td><td>1</td><td>0</td><td>0</td><td>0</td></tr>"
            ),
            payload,
        )
        self.assertIn(
            (
                "<tr><td>Cisco Unified Client Services Framework</td><td>SIP</td><td>—</td>"
                "<td>1</td><td>0</td><td>0</td><td>0</td><td>0</td><td>1</td></tr>"
            ),
            payload,
        )

    def test_html_report_correlates_static_configured_and_runtime_loads(self) -> None:
        facts = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="SEP000000000001",
                    description=None,
                    model="Cisco 8845",
                    protocol="SIP",
                    device_pool="Default",
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load="sip8845.pilot",
                    source="fixture",
                )
            ],
            device_load_defaults=[
                DeviceLoadDefaultFact(
                    model="Cisco 8845",
                    protocol="SIP",
                    default_load="sip8845.default",
                    source="fixture",
                )
            ],
            registrations=[
                DeviceRegistrationFact(
                    name="SEP000000000001",
                    status="registered",
                    registered_node="pub",
                    ip_address=None,
                    model="Cisco 8845",
                    protocol="SIP",
                    source="fixture",
                    active_load="sip8845.pilot",
                )
            ],
        )

        payload = HtmlReportBuilder().build(
            AssessmentReport(facts=facts, collector_results=[], findings=[])
        )

        self.assertIn("Active load matches static override</td><td>1", payload)
        self.assertIn("sip8845.pilot</td><td>1", payload)

    def test_html_report_excludes_cti_noise_and_correlates_download_failures(self) -> None:
        facts = AssessmentFacts(
            devices=[
                DeviceInventoryFact(
                    name="SEP1",
                    description=None,
                    model="Cisco 7841",
                    protocol="SIP",
                    device_pool=None,
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="fixture",
                ),
                DeviceInventoryFact(
                    name="CTI1",
                    description=None,
                    model="CTI Port",
                    protocol="SCCP",
                    device_pool=None,
                    call_manager_group=None,
                    location=None,
                    region=None,
                    configured_load=None,
                    source="fixture",
                ),
            ],
            device_load_defaults=[
                DeviceLoadDefaultFact(
                    model="Cisco 7841",
                    protocol="SIP",
                    default_load="sip78.current",
                    source="fixture",
                )
            ],
            registrations=[
                DeviceRegistrationFact(
                    name="SEP1",
                    status="registered",
                    registered_node="sub1",
                    ip_address=None,
                    model="Cisco 7841",
                    protocol="SIP",
                    source="fixture",
                    active_load="sip78.old",
                    download_status="Failed",
                    download_failure_reason="No Tftp server set",
                ),
                DeviceRegistrationFact(
                    name="CTI1",
                    status="registered",
                    registered_node="sub1",
                    ip_address=None,
                    model="CTI Port",
                    protocol="SCCP",
                    source="fixture",
                ),
            ],
        )

        payload = HtmlReportBuilder().build(
            AssessmentReport(facts=facts, collector_results=[], findings=[])
        )

        self.assertIn("Download failed; active load differs from intended load</td><td>1", payload)
        self.assertIn("No Tftp server set", payload)
        self.assertIn("Firmware differs from the intended load after a failed download", payload)
        self.assertNotIn("<td>CTI Port</td><td>SCCP</td><td>Unavailable</td>", payload)

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
            "<tr><td>Gateways/endpoints</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>SIP trunks</td><td>0</td><td>0</td><td>0</td><td>0</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>Gateways</td><td>1</td><td>0</td><td>0</td><td>1</td></tr>",
            payload,
        )
        self.assertIn(
            "<tr><td>SIP Trunks</td><td>0</td><td>1</td><td>0</td><td>1</td></tr>",
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
                "Unity Connection inventory",
                "Unity Connection configuration",
                "Unity Connection experimental SQL",
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
        self.assertEqual(by_name["Unity Connection inventory"].status, "empty")
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
        self.assertEqual(
            [registration.name for registration in reconciliation.runtime_only_resources],
            ["HQ-VG01"],
        )
        self.assertEqual(reconciliation.runtime_only_endpoints, [])

    def test_runtime_resource_categories_cover_observed_cucm_classes_and_models(self) -> None:
        cases = (
            ("SIPTrunk", "131", "SIP Trunks"),
            ("HuntList", "90", "Route Lists"),
            ("H323", "62", "H.323 Gateways"),
            ("Cti", "73", "CTI Route Points"),
            ("MediaResources", "126", "Annunciators"),
            ("MediaResources", "50", "Conference Bridges"),
            ("MediaResources", "112", "Transcoders"),
            ("MediaResources", "110", "Media Termination Points"),
            ("MediaResources", "70", "Music On Hold"),
            ("MediaResources", "36219", "IVR Media Resources"),
        )
        for device_class, model_code, expected in cases:
            with self.subTest(device_class=device_class, model_code=model_code):
                registration = DeviceRegistrationFact(
                    name=f"RESOURCE-{model_code}",
                    status="Registered",
                    registered_node="pub",
                    ip_address=None,
                    model=model_code,
                    protocol="Any",
                    source="RISPort70.selectCmDevice",
                    runtime_model_code=model_code,
                    device_class=device_class,
                )
                self.assertEqual(runtime_resource_category(registration), expected)

    def test_html_reconciliation_section_is_informational_only(self) -> None:
        payload = HtmlReportBuilder().build(self.report)

        self.assertIn("Call Manager Runtime Resources", payload)
        self.assertIn("Unmatched Runtime Endpoint Records", payload)
        self.assertIn("HQ-VG01", payload)
        self.assertIn("ITSP-SIP-TRUNK", payload)
        self.assertIn("health findings.", payload)
        self.assertNotIn("inventory.runtime_reconciliation", payload)

    def test_customer_report_omits_infrastructure_chapter_and_relocates_cuc_health(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                configuration_objects=[
                    ConfigurationObjectFact(
                        object_type="CucMailboxInventory",
                        name="Mailboxes",
                        details={"total": "10"},
                        source="CUC.CUPI.GET",
                    ),
                    ConfigurationObjectFact(
                        object_type="CucPhoneSystem",
                        name="Phone System",
                        details={},
                        source="CUC.CUPI.GET",
                    ),
                ],
                platform_checks=[
                    PlatformCheckFact("cuc-pub", "show status", "ok", {}, "CUC.UCOS.CLI")
                ],
            ),
            collector_results=[],
            findings=[],
        )

        engineering = HtmlReportBuilder().build(report)

        self.assertIn("Infrastructure and Inventory", engineering)
        self.assertIn("Unity Connection Inventory", engineering)
        self.assertIn("Unity Connection Configuration", engineering)
        for template in available_report_templates():
            customer = HtmlReportBuilder(customer_safe=True, template=template).build(report)
            self.assertNotIn("Infrastructure and Inventory", customer)
            self.assertNotIn("04 / INFRASTRUCTURE", customer)
            self.assertIn("04 / ANALYSIS", customer)
            self.assertIn("05 / EVIDENCE", customer)
            self.assertNotIn("Unity Connection Inventory", customer)
            self.assertNotIn("Unity Connection Configuration", customer)
            self.assertIn("Unity Connection Platform Health", customer)
            self.assertLess(
                customer.index("Collection Coverage"),
                customer.index("Unity Connection Platform Health"),
            )
            self.assertLess(
                customer.index("Unity Connection Platform Health"),
                customer.index("<h2>Cluster</h2>"),
            )

    def test_cucm_runtime_resources_and_missing_endpoints_are_reported_separately(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP-MISSING",
                        description=None,
                        model="Cisco 8841",
                        protocol="SIP",
                        device_pool="School-A",
                        call_manager_group=None,
                        location="Hub_None",
                        region=None,
                        configured_load=None,
                        source="AXL.listPhone.summary",
                    ),
                    DeviceInventoryFact(
                        name="Auto-registration Template",
                        description=None,
                        model="Universal Device Template",
                        protocol="SIP",
                        device_pool="Default",
                        call_manager_group=None,
                        location="Hub_None",
                        region=None,
                        configured_load=None,
                        source="AXL.listPhone.summary",
                    ),
                ],
                registrations=[
                    DeviceRegistrationFact(
                        "TRUNK-1",
                        "Registered",
                        "pub",
                        None,
                        "131",
                        "Any",
                        "RISPort70.selectCmDevice",
                        runtime_model_code="131",
                        device_class="SIPTrunk",
                    ),
                    DeviceRegistrationFact(
                        "ANN-PUB",
                        "Registered",
                        "pub",
                        None,
                        "126",
                        "Any",
                        "RISPort70.selectCmDevice",
                        runtime_model_code="126",
                        device_class="MediaResources",
                    ),
                    DeviceRegistrationFact(
                        "UNMATCHED-PHONE",
                        "Unknown",
                        None,
                        None,
                        "Cisco 8841",
                        "SIP",
                        "RISPort70.selectCmDeviceExt",
                        device_class="Phone",
                    ),
                ],
            ),
            collector_results=[],
            findings=[],
        )

        payload = HtmlReportBuilder(customer_safe=True).build(report)
        reconciliation = payload[
            payload.index("<h2>Inventory / Runtime Reconciliation</h2>") : payload.index(
                "<h2>Detailed Device Inventory</h2>"
            )
        ]

        self.assertIn("Configured Endpoint Runtime Coverage", payload)
        self.assertIn("Hub_None", payload)
        self.assertIn("did not cause the missing runtime observations", payload)
        self.assertIn("Call Manager Runtime Resources", payload)
        self.assertIn("SIP Trunks", payload)
        self.assertIn("Annunciators", payload)
        self.assertIn("TRUNK-1", payload)
        self.assertIn("ANN-PUB", payload)
        self.assertNotIn("TRUNK-1", reconciliation)
        self.assertNotIn("ANN-PUB", reconciliation)
        self.assertIn("UNMATCHED-PHONE", reconciliation)
        self.assertNotIn("Inventory-only Registration-capable or Unclassified Devices", payload)

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

    def test_html_report_marks_zero_only_cpu_unavailable(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                perf_counters=[
                    PerfCounterFact(
                        node="cucm-pub-01",
                        object_name="Processor",
                        counter_name="% CPU Time",
                        instance="_Total",
                        value=0,
                        sample_count=2,
                        source="PerfMon.perfmonCollectCounterData",
                    )
                ]
            ),
            collector_results=[],
            findings=[],
        )

        payload = HtmlReportBuilder().build(report)

        self.assertIn("CPU percentage unavailable", payload)
        self.assertIn("Unavailable (zero-only snapshot)", payload)

    def test_customer_deliverable_retains_identifiers_but_omits_artifact_paths(self) -> None:
        report = AssessmentReport(
            facts=AssessmentFacts(
                devices=[
                    DeviceInventoryFact(
                        name="SEP001122334455",
                        description="Principal office",
                        model="Cisco 8841",
                        protocol="SIP",
                        device_pool="Private-Pool",
                        call_manager_group=None,
                        location="Private-Site",
                        region=None,
                        configured_load=None,
                        source="AXL.listPhone.summary",
                    )
                ]
            ),
            collector_results=[
                CollectionResult(
                    collector_name="axl",
                    facts=AssessmentFacts(),
                    evidence=[
                        EvidenceRef(
                            source="AXL",
                            operation="listPhone",
                            node="private-publisher.example",
                            artifact_path=Path("private/artifact/response.txt"),
                            confidence="high",
                            parser="fixture",
                        )
                    ],
                )
            ],
            findings=[],
            runtime_metadata={
                "profile_name": "PrivateCustomer",
                "publisher": "private-publisher.example",
            },
        )

        payload = HtmlReportBuilder(customer_safe=True).build(report)

        self.assertIn("SEP001122334455", payload)
        self.assertIn("PrivateCustomer", payload)
        self.assertIn("private-publisher.example", payload)
        self.assertNotIn("private/artifact/response.txt", payload)
        self.assertIn("Customer-safe HTML</th><td>Enabled", payload)

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
