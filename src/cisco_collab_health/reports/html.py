"""Styled HTML report builder."""

from __future__ import annotations

from base64 import b64encode
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from html import escape
from pathlib import Path

from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import (
    CertificateFact,
    ConfigurationObjectFact,
    DeviceInventoryFact,
    DeviceRegistrationFact,
)
from cisco_collab_health.models.findings import FindingSeverity, HealthFinding
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.formatting import (
    display_bool,
    display_details,
    display_duration,
    display_source,
    display_status_label,
    display_text,
)
from cisco_collab_health.reports.reconciliation import (
    build_inventory_runtime_reconciliation,
)


@dataclass(frozen=True)
class ReportTemplate:
    """Presentation metadata for a named HTML report template."""

    key: str
    title: str
    eyebrow: str
    tagline: str


@dataclass(frozen=True)
class ReportTheme:
    """Standalone asset slots and tokens for one report presentation theme."""

    key: str
    asset_directory: str
    slots: dict[str, str]
    colors: dict[str, str]
    hero_overlay: str
    hero_focal_point: str
    watermark_opacity: str
    show_hero_logo: bool
    show_footer_logo: bool


REPORT_TEMPLATES = {
    "aletheiauc": ReportTemplate(
        key="aletheiauc",
        title="AletheiaUC Assessment",
        eyebrow="Engineering health brief",
        tagline="Bringing UC Health to Light",
    ),
    "comsource": ReportTemplate(
        key="comsource",
        title="ComSource Collaboration Health Assessment",
        eyebrow="Customer assessment report",
        tagline="Collaboration platform health and readiness",
    ),
}


REPORT_THEMES = {
    "aletheiauc": ReportTheme(
        key="aletheiauc",
        asset_directory="aletheiauc",
        slots={
            "logo-primary": "repository:assets/brand/svg/aletheiauc-logo-lockup.svg",
            "hero-background": "hero-techno-sorcery-3198x800.jpg",
            "executive-background": "executive-background-2400x960.jpg",
            "chapter-findings": "chapter-findings-2400x240.jpg",
            "chapter-scope": "chapter-scope-2400x240.jpg",
            "chapter-infrastructure": "chapter-infrastructure-2400x240.jpg",
            "chapter-analysis": "chapter-analysis-2400x240.jpg",
            "chapter-evidence": "chapter-evidence-2400x240.jpg",
            "recommendation-background": "recommendation-background-2400x240.jpg",
            "section-band": "section-band-2400x240.jpg",
            "divider-horizontal": "divider-horizontal.svg",
            "watermark": "watermark.svg",
            "footer-background": "footer-techno-sorcery-2397x220.jpg",
            "status-icons": "status-icons.svg",
        },
        colors={
            "page": "#050812",
            "surface": "#10182B",
            "text": "#E6E8F1",
            "muted": "#98A2B8",
            "accent": "#6A4CFF",
            "cyan": "#22D3EE",
            "gold": "#FFC75E",
        },
        hero_overlay="linear-gradient(90deg,rgba(5,8,18,.96) 0%,rgba(10,15,30,.86) 46%,rgba(10,15,30,.18) 100%)",
        hero_focal_point="72% 50%",
        watermark_opacity=".06",
        show_hero_logo=False,
        show_footer_logo=False,
    ),
    "comsource": ReportTheme(
        key="comsource",
        asset_directory="comsource",
        slots={
            "logo-primary": "ComSource_Logo.svg",
            "hero-background": "hero-background.svg",
            "executive-background": "section-band.svg",
            "chapter-findings": "section-band.svg",
            "chapter-scope": "section-band.svg",
            "chapter-infrastructure": "section-band.svg",
            "chapter-analysis": "section-band.svg",
            "chapter-evidence": "section-band.svg",
            "recommendation-background": "section-band.svg",
            "section-band": "section-band.svg",
            "divider-horizontal": "divider-horizontal.svg",
            "watermark": "watermark.svg",
            "footer-background": "footer-background.svg",
            "status-icons": "status-icons.svg",
        },
        colors={
            "page": "#EAF7FC",
            "surface": "#FFFFFF",
            "text": "#20283A",
            "muted": "#667085",
            "accent": "#2E1D67",
            "cyan": "#0096D6",
            "gold": "#0096D6",
        },
        hero_overlay="linear-gradient(90deg,rgba(8,13,34,.98) 0%,rgba(16,22,51,.9) 48%,rgba(46,29,103,.25) 100%)",
        hero_focal_point="72% 50%",
        watermark_opacity=".05",
        show_hero_logo=True,
        show_footer_logo=True,
    ),
}


@lru_cache(maxsize=None)
def _theme_asset_data_uri(theme: str, slot: str) -> str:
    """Resolve one named asset slot as a standalone data URI."""

    package = REPORT_THEMES[theme]
    filename = package.slots[slot]
    if filename.startswith("repository:"):
        path = Path(__file__).parents[3] / filename.removeprefix("repository:")
    else:
        path = Path(__file__).with_name("assets") / package.asset_directory / filename
    mime = {
        ".svg": "image/svg+xml",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }[path.suffix.lower()]
    return f"data:{mime};base64,{b64encode(path.read_bytes()).decode('ascii')}"


class HtmlReportBuilder:
    """Builds a styled standalone HTML report."""

    def __init__(self, *, customer_safe: bool = False, template: str = "aletheiauc") -> None:
        self.customer_safe = customer_safe
        try:
            self.template = REPORT_TEMPLATES[template]
            self.theme = REPORT_THEMES[template]
        except KeyError as exc:
            available = ", ".join(sorted(REPORT_TEMPLATES))
            raise ValueError(
                f"Unknown HTML report template '{template}'. Available: {available}."
            ) from exc

    def build(self, report: AssessmentReport) -> str:
        severity_counts = Counter(finding.severity for finding in report.findings)
        collector_note_count = sum(len(result.notes) for result in report.collector_results)
        collector_issue_count = sum(
            len(result.warnings) + len(result.errors) for result in report.collector_results
        )
        collector_evidence_count = sum(len(result.evidence) for result in report.collector_results)
        header_metadata = self._header_metadata(report)
        hero_image = _theme_asset_data_uri(self.template.key, "hero-background")
        watermark_image = _theme_asset_data_uri(self.template.key, "watermark")
        section_band_image = _theme_asset_data_uri(self.template.key, "section-band")
        executive_image = _theme_asset_data_uri(self.template.key, "executive-background")
        chapter_findings_image = _theme_asset_data_uri(self.template.key, "chapter-findings")
        chapter_scope_image = _theme_asset_data_uri(self.template.key, "chapter-scope")
        chapter_infrastructure_image = _theme_asset_data_uri(
            self.template.key, "chapter-infrastructure"
        )
        chapter_analysis_image = _theme_asset_data_uri(self.template.key, "chapter-analysis")
        chapter_evidence_image = _theme_asset_data_uri(self.template.key, "chapter-evidence")
        recommendation_image = _theme_asset_data_uri(self.template.key, "recommendation-background")
        footer_image = _theme_asset_data_uri(self.template.key, "footer-background")
        logo_image = _theme_asset_data_uri(self.template.key, "logo-primary")
        template_css = (
            self._comsource_css() if self.template.key == "comsource" else self._aletheiauc_css()
        )
        template_header = self._template_header(
            header_metadata,
            hero_image=hero_image,
            logo_image=logo_image,
        )
        template_footer = self._template_footer(logo_image=logo_image, footer_image=footer_image)
        methodology_scope_section = self._methodology_scope_section(report)
        target_scope_section = self._target_scope_section(report)
        cuc_inventory_section = self._cuc_inventory_section(report)
        cuc_configuration_section = self._cuc_configuration_section(report)
        cuc_platform_section = self._cuc_platform_section(report)
        cuc_informix_section = self._cuc_informix_section(report)
        cluster_section = self._cluster_section(report)
        node_rows = self._node_rows(report)
        device_rows = self._device_rows(report)
        device_model_rows = self._device_model_summary_rows(report)
        device_load_rows = self._device_load_summary_rows(report)
        device_load_note = (
            '<p class="meta">Device load defaults were unavailable; static overrides remain '
            "identifiable, but default comparison is unavailable.</p>"
            if report.facts.devices and not report.facts.device_load_defaults
            else ""
        )
        static_load_rows = self._static_load_summary_rows(report)
        firmware_correlation_rows = self._firmware_correlation_rows(report)
        coverage_section = self._coverage_section(report)
        registration_rows = self._registration_rows(report)
        registration_summary_rows = self._registration_summary_rows(report)
        firmware_summary_rows = self._firmware_summary_rows(report)
        firmware_failure_rows = self._firmware_failure_rows(report)
        firmware_failure_detail_rows = self._firmware_failure_detail_rows(report)
        firmware_exception_rows = self._firmware_exception_rows(report)
        mixed_firmware_rows = self._mixed_firmware_rows(report)
        reconciliation_section = self._reconciliation_section(report)
        service_rows = self._service_rows(report)
        service_summary_rows = self._service_summary_rows(report)
        service_group_summary_rows = self._service_group_summary_rows(report)
        service_reason_rows = self._service_reason_rows(report)
        perf_counter_rows = self._perf_counter_rows(report)
        perf_summary_rows = self._perf_summary_rows(report)
        cpu_note = self._cpu_availability_note(report)
        configuration_summary_rows = self._configuration_summary_rows(report)
        route_pattern_rows = self._route_pattern_relationship_rows(report)
        route_list_rows = self._route_list_relationship_rows(report)
        css_coverage_rows = self._css_partition_coverage_rows(report)
        hunt_topology_rows = self._configuration_family_rows(
            report, {"HuntPilot", "HuntList", "LineGroup", "Line"}
        )
        integration_security_rows = self._configuration_family_rows(
            report,
            {
                "SipTrunk",
                "SipProfile",
                "SipTrunkSecurityProfile",
                "LdapDirectory",
                "PhoneSecurityProfile",
            },
        )
        media_topology_rows = self._configuration_family_rows(
            report,
            {"MediaResourceGroup", "MediaResourceList", "ConferenceBridge", "Transcoder", "Mtp"},
        )
        service_deployment_rows = self._service_deployment_rows(report)
        configuration_rows = self._configuration_rows(report)
        platform_check_rows = self._platform_check_rows(report)
        certificate_rows = self._certificate_rows(report)
        collector_issues_section = self._collector_issues_section(report)
        collector_notes_section = self._collector_notes_section(report)
        collector_evidence_section = self._collector_evidence_section(report)
        priority_findings = [
            finding
            for finding in report.findings
            if finding.severity in {FindingSeverity.CRITICAL, FindingSeverity.WARNING}
        ]
        observations = [
            finding for finding in report.findings if finding.severity == FindingSeverity.INFO
        ]
        priority_sections = "\n".join(
            self._finding_section(finding) for finding in priority_findings
        )
        if not priority_sections:
            priority_sections = (
                "<p>No critical or warning findings were identified in the collected data.</p>"
            )
        observations_section = ""
        if observations:
            observation_cards = "\n".join(
                self._finding_section(finding) for finding in observations
            )
            observations_section = f"""
      <details class=\"finding-observations\">
        <summary>Assessment observations ({len(observations)})</summary>
        {observation_cards}
      </details>"""
        findings_section = (
            f'<section class="findings-section rds-section"><h2>Priority Findings</h2>'
            f'<p class="meta finding-intro">Issues below need attention. Each includes what was found, why it matters, and the recommended next step.</p>'
            f"{priority_sections}{observations_section}</section>"
        )
        certificate_summary = self._certificate_summary(report)
        executive_overview = self._executive_overview(
            report,
            severity_counts=severity_counts,
            collector_note_count=collector_note_count,
            collector_issue_count=collector_issue_count,
            collector_evidence_count=collector_evidence_count,
        )
        findings_chapter = self._chapter_header(
            "02 / FINDINGS",
            "Findings and Observations",
            "Observed conditions, operational impact, and action priority",
            "findings",
        )
        scope_chapter = self._chapter_header(
            "03 / SCOPE",
            "Scope and Method",
            "Targets, data sources, boundaries, and confidence",
            "scope",
        )
        infrastructure_chapter = self._chapter_header(
            "04 / INFRASTRUCTURE",
            "Infrastructure and Inventory",
            "CUCM and Unity Connection topology, objects, and runtime state",
            "infrastructure",
        )
        analysis_chapter = self._chapter_header(
            "05 / ANALYSIS",
            "Discovery and Analysis",
            "Collection depth across topology, services, firmware, and configuration",
            "analysis",
        )
        evidence_chapter = self._chapter_header(
            "06 / EVIDENCE",
            "Appendices and Engineering Evidence",
            "Collector detail, reconciliation, provenance, and inventories",
            "evidence",
        )

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(self.template.title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #eef2ff;
      --panel: rgba(255, 255, 255, 0.94);
      --text: #151a31;
      --muted: #526079;
      --line: #d9ddf0;
      --midnight: #0a0f1e;
      --violet: #6a4cff;
      --blue: #2f7cff;
      --cyan: #22d3ee;
      --gold: #ffc75e;
      --critical: #b42318;
      --warning: #b54708;
      --info: #2f7cff;
    }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at 10% -10%, rgba(47, 124, 255, 0.18), transparent 30rem),
        radial-gradient(circle at 95% 4%, rgba(106, 76, 255, 0.14), transparent 26rem),
        var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.45;
    }}
    header {{
      position: relative;
      overflow: hidden;
      background: linear-gradient(118deg, var(--midnight), #172554 57%, #302166);
      color: white;
      padding: 30px max(32px, calc((100vw - 1120px) / 2 + 20px));
    }}
    header::after {{
      content: "";
      position: absolute;
      width: 340px;
      height: 340px;
      right: -100px;
      top: -185px;
      background: radial-gradient(circle, rgba(34, 211, 238, 0.30), transparent 66%);
      pointer-events: none;
    }}
    .masthead {{
      position: relative;
      z-index: 1;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
    }}
    header h1 {{
      margin: 4px 0 8px;
      font-size: clamp(28px, 4vw, 38px);
      letter-spacing: -0.03em;
    }}
    header p {{
      margin: 0;
      color: #d7e5ff;
    }}
    .eyebrow {{
      color: var(--gold);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.13em;
      text-transform: uppercase;
    }}
    .beacon {{
      display: grid;
      place-items: center;
      width: 64px;
      height: 64px;
      border: 1px solid rgba(255, 255, 255, 0.30);
      border-radius: 50%;
      color: var(--gold);
      font-size: 27px;
      background: radial-gradient(circle, rgba(255, 199, 94, 0.24), rgba(34, 211, 238, 0.05));
      box-shadow: 0 0 0 8px rgba(255, 255, 255, 0.04), 0 0 45px rgba(34, 211, 238, 0.22);
    }}
    .capability-row {{
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin-top: 22px;
      color: #dce9ff;
      font-size: 13px;
    }}
    .capability-row span {{
      padding: 4px 9px;
      border: 1px solid rgba(255, 255, 255, 0.16);
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.06);
    }}
    .header-meta {{
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
      margin-top: 14px;
    }}
    .meta-chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      border: 1px solid rgba(255, 255, 255, 0.18);
      border-radius: 999px;
      background: rgba(5, 8, 18, 0.28);
      color: #eaf2ff;
      font-size: 13px;
      font-weight: 700;
    }}
    .meta-chip::before {{
      content: "✦";
      color: var(--violet);
    }}
    .meta-chip.scope {{
      border-color: rgba(34, 211, 238, 0.48);
      color: #d8fbff;
    }}
    .meta-chip.diagnostic {{
      border-color: rgba(255, 199, 94, 0.48);
      color: #fff0cf;
    }}
    main {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    section {{
      margin: 0 0 24px;
      padding: 22px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 12px 30px rgba(15, 23, 42, 0.07);
      overflow-x: auto;
    }}
    h2 {{
      margin: 0 0 16px;
      font-size: 20px;
    }}
    h3 {{
      margin: 0 0 10px;
      font-size: 17px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
    }}
    .metric {{
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: linear-gradient(145deg, #ffffff, #f3f6ff);
      box-shadow: inset 0 2px 0 rgba(47, 124, 255, 0.10);
    }}
    .metric strong {{
      display: block;
      font-size: 24px;
      margin-bottom: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    .table-scroll {{
      width: 100%;
      overflow-x: auto;
      margin-bottom: 14px;
    }}
    .table-scroll table {{
      min-width: 760px;
    }}
    details > summary {{
      cursor: pointer;
      color: var(--info);
      font-weight: 700;
      margin: 8px 0 14px;
    }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
    }}
    .finding {{
      border-left: 5px solid var(--info);
    }}
    .finding.critical {{
      border-left-color: var(--critical);
    }}
    .finding.warning {{
      border-left-color: var(--warning);
    }}
    .finding.info {{
      border-left-color: var(--info);
    }}
    .finding-observations {{ margin: 18px 20px 0; }}
    .finding-observations .finding {{ margin-left: 0; margin-right: 0; }}
    .meta {{
      color: var(--muted);
      font-size: 14px;
      margin-bottom: 12px;
    }}
    .facts {{
      margin: 8px 0 0;
      padding-left: 20px;
    }}
    /* Default standalone report treatment. */
    :root {{
      color-scheme: dark;
      --bg: #050812;
      --panel: #10182b;
      --text: #e6e8f1;
      --muted: #98a2b8;
      --line: #263451;
      --critical: #ff5576;
      --warning: #ffc75e;
      --info: #22d3ee;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      background:
        radial-gradient(circle at 82% 4%, rgba(106, 76, 255, 0.22), transparent 31rem),
        radial-gradient(circle at 12% 2%, rgba(34, 211, 238, 0.11), transparent 28rem),
        linear-gradient(180deg, #050812, var(--midnight) 34rem);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    .report-shell {{ width: min(1480px, calc(100% - 40px)); margin: 0 auto; padding: 30px 0 70px; }}
    .report-hero {{
      min-height: clamp(280px, 32vw, 440px);
      padding: 32px clamp(24px, 5vw, 64px);
      border: 1px solid rgba(106, 76, 255, 0.45);
      border-radius: 18px;
      background: linear-gradient(90deg, rgba(5, 8, 18, 0.84), rgba(5, 8, 18, 0.20)), var(--hero-image) center/cover;
      box-shadow: 0 18px 45px rgba(0, 0, 0, 0.28);
    }}
    .report-hero::after {{
      width: 420px;
      height: 420px;
      right: -110px;
      top: -175px;
      background: radial-gradient(circle, rgba(34, 211, 238, 0.24), transparent 67%);
    }}
    .report-hero .masthead {{ min-height: 185px; align-items: flex-start; }}
    .report-hero h1 {{ font-size: clamp(32px, 4vw, 46px); max-width: 680px; }}
    .report-hero .beacon {{ width: 72px; height: 72px; }}
    .report-hero .header-meta {{ justify-content: flex-start; max-width: 760px; }}
    main {{ max-width: none; padding: 0; }}
    section {{
      position: relative;
      margin: 25px 0 0;
      padding: 0;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: linear-gradient(180deg, rgba(21, 31, 54, 0.94), rgba(16, 24, 43, 0.94));
      box-shadow: 0 12px 30px rgba(0, 0, 0, 0.18);
    }}
    section::before {{
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      opacity: 0.055;
      background: var(--emblem-image) 97% 14% / 310px no-repeat;
    }}
    section > * {{ position: relative; z-index: 1; }}
    section > h2 {{
      margin: 0 0 16px;
      padding: 17px 20px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(90deg, rgba(106, 76, 255, 0.13), rgba(34, 211, 238, 0.025));
      font-size: 20px;
    }}
    section > :not(h2) {{ margin-left: 20px; margin-right: 20px; }}
    section > table, section > .table-scroll {{ width: calc(100% - 40px); }}
    .summary-grid {{ padding: 0 20px 20px; }}
    .metric {{
      background: linear-gradient(145deg, rgba(21, 31, 54, 0.96), rgba(5, 8, 18, 0.66));
      border-color: rgba(38, 52, 81, 0.95);
      box-shadow: inset 0 2px 0 rgba(47, 124, 255, 0.14);
    }}
    th, td {{ border-bottom-color: rgba(38, 52, 81, 0.76); }}
    th {{ color: var(--cyan); background: rgba(13, 21, 40, 0.86); }}
    tbody tr:nth-child(even) {{ background: rgba(255, 255, 255, 0.018); }}
    tbody tr:hover {{ background: rgba(47, 124, 255, 0.06); }}
    .meta {{ color: var(--muted); }}
    .technology-section.cuc-section {{ border-color: rgba(34, 211, 238, 0.40); }}
    .finding {{
      margin: 10px 20px;
      padding: 14px 16px;
      border: 1px solid var(--line);
      border-left: 4px solid var(--info);
      border-radius: 6px;
      background: rgba(5, 8, 18, 0.38);
    }}
    @media (max-width: 720px) {{
      .report-shell {{ width: min(100% - 20px, 1480px); padding-top: 10px; }}
      .report-hero {{ min-height: 340px; }}
      .report-hero .masthead {{ min-height: 195px; }}
      .report-hero .beacon {{ display: none; }}
      .report-hero .header-meta {{ justify-content: center; }}
    }}
    @media print {{
      :root {{ color-scheme: light; }}
      body {{ background: #fff !important; color: #111 !important; }}
      .report-shell {{ width: 100%; padding: 0; }}
      .report-hero {{ min-height: 155px; background: #fff !important; border: 2px solid #20283a; box-shadow: none; }}
      .report-hero::after, section::before, .beacon {{ display: none !important; }}
      .report-hero h1, .report-hero p, .meta {{ color: #111 !important; }}
      section, .metric, .finding {{ background: #fff !important; color: #111 !important; box-shadow: none !important; }}
      section {{ border-color: #cbd1dc; break-inside: avoid; }}
      th, td {{ border-color: #d8dce5; }}
      th {{ color: #245ec9; background: #f2f5fa; }}
    }}
    {template_css}
    {self._design_system_css()}
  </style>
</head>
<body class="{escape(self.template.key)}-report">
  <div class="report-shell rds-report" style="--watermark-image: url('{watermark_image}'); --section-band-image: url('{section_band_image}'); --executive-image: url('{executive_image}'); --chapter-findings-image: url('{chapter_findings_image}'); --chapter-scope-image: url('{chapter_scope_image}'); --chapter-infrastructure-image: url('{chapter_infrastructure_image}'); --chapter-analysis-image: url('{chapter_analysis_image}'); --chapter-evidence-image: url('{chapter_evidence_image}'); --recommendation-image: url('{recommendation_image}');">
  <header class="report-hero rds-hero" style="--hero-image: url('{hero_image}');">
    {template_header}
  </header>
  {self._report_transition()}
  <main>
    {executive_overview}
    {findings_chapter}
    {findings_section}
    {scope_chapter}
    {methodology_scope_section}
    {target_scope_section}
    {infrastructure_chapter}
    {cuc_inventory_section}
    {cuc_configuration_section}
    {cuc_platform_section}
    {cuc_informix_section}
    {analysis_chapter}
    {coverage_section}
    {cluster_section}
    <section>
      <h2>Discovered Nodes</h2>
      {self._node_source_caption(report)}
      <table>
        <thead><tr><th>Technology</th><th>Name</th><th>Address</th><th>Role</th><th>Reachable</th></tr></thead>
        <tbody>
          {node_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Device Inventory By Model</h2>
      {_source_caption("Device Inventory By Model", report)}
      <table>
        <thead>
          <tr>
            <th>Model</th><th>SIP</th><th>SCCP</th><th>Other</th><th>Total</th>
          </tr>
        </thead>
        <tbody>
          {device_model_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Device Registration Summary</h2>
      {_source_caption("Device Registration Summary", report)}
      <table>
        <thead>
          <tr>
            <th>Category</th><th>Registered</th><th>Unregistered</th><th>Other</th><th>Total</th>
          </tr>
        </thead>
        <tbody>
          {registration_summary_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Device Load Summary</h2>
      {_source_caption("Device Load Summary", report)}
      {device_load_note}
      <table>
        <thead>
          <tr>
            <th>Model</th><th>Protocol</th><th>Default Load</th>
            <th>Devices</th><th>Static Overrides</th><th>Overrides Matching Default</th>
            <th>Overrides Differing</th><th>Override Default Unknown</th><th>Inherited Default</th>
          </tr>
        </thead>
        <tbody>
          {device_load_rows}
        </tbody>
      </table>
      <h3>Static Overrides by Model and Load</h3>
      <table>
        <thead><tr><th>Model</th><th>Protocol</th><th>Static Load</th><th>Devices</th></tr></thead>
        <tbody>{static_load_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Runtime Firmware and Downloads</h2>
      <p class="meta">Source: RISPort runtime firmware and download state. Unknown download
      status is reported as unknown and is not treated as a failure.</p>
      <table>
        <thead><tr><th>Model</th><th>Protocol</th><th>Active Load</th><th>Devices</th></tr></thead>
        <tbody>{firmware_summary_rows}</tbody>
      </table>
      <h3>Configured / Runtime Firmware Correlation</h3>
      <table>
        <thead><tr><th>State</th><th>Devices</th></tr></thead>
        <tbody>{firmware_correlation_rows}</tbody>
      </table>
      <h3>Mixed Active Firmware Populations</h3>
      <table>
        <thead><tr><th>Model</th><th>Protocol</th><th>Active Loads</th><th>Runtime</th><th>Configured</th></tr></thead>
        <tbody>{mixed_firmware_rows}</tbody>
      </table>
      <h3>Explicit Download Failures</h3>
      <table>
        <thead><tr><th>Reason</th><th>Devices</th></tr></thead>
        <tbody>{firmware_failure_rows}</tbody>
      </table>
      <h3>Download Failures by Model and Node</h3>
      <table>
        <thead><tr><th>Model</th><th>Node</th><th>Reason</th><th>Devices</th></tr></thead>
        <tbody>{firmware_failure_detail_rows}</tbody>
      </table>
      <h3>Firmware Exceptions</h3>
      <table>
        <thead><tr><th>Impact / next step</th><th>Device</th><th>Model</th><th>Static Load</th><th>Default Load</th>
        <th>Active Load</th><th>Download Status</th><th>Failure Reason</th><th>Node</th></tr></thead>
        <tbody>{firmware_exception_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Services</h2>
      {_source_caption("Services", report)}
      <table>
        <thead><tr><th>Node</th><th>Started</th><th>Stopped</th><th>Total</th></tr></thead>
        <tbody>{service_summary_rows}</tbody>
      </table>
      <h3>Non-started Service Reasons</h3>
      <table>
        <thead><tr><th>Reason</th><th>Services</th></tr></thead>
        <tbody>{service_reason_rows}</tbody>
      </table>
      <h3>Service Status by Group</h3>
      <table>
        <thead><tr><th>Group</th><th>Started</th><th>Stopped</th><th>Total</th></tr></thead>
        <tbody>{service_group_summary_rows}</tbody>
      </table>
      <h3>Service Deployment Comparison</h3>
      <p class="meta">Observed deployment only; differences are not evaluated against an assumed node-role policy.</p>
      <details><summary>Show service deployment by node</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Service</th><th>Group</th><th>Started Nodes</th><th>Stopped Nodes</th></tr></thead>
        <tbody>{service_deployment_rows}</tbody>
      </table></div>
      </details>
      <details>
        <summary>Show all service records</summary>
      <table>
        <thead>
          <tr>
            <th>Node</th><th>Service</th><th>Type</th><th>Group</th><th>Status</th>
            <th>Uptime</th><th>Reason</th><th>Source</th>
          </tr>
        </thead>
        <tbody>
          {service_rows}
        </tbody>
      </table>
      </details>
    </section>
    <section>
      <h2>Performance Counters</h2>
      {_source_caption("Performance Counters", report)}
      {cpu_note}
      <p class="meta">Memory values are point-in-time observations; no memory health threshold is applied.</p>
      <table>
        <thead><tr><th>Node</th><th>Metric</th><th>Value</th><th>Samples</th></tr></thead>
        <tbody>{perf_summary_rows}</tbody>
      </table>
      <details>
        <summary>Show all performance counter records</summary>
      <table>
        <thead>
          <tr>
            <th>Node</th><th>Object</th><th>Counter</th><th>Instance</th>
            <th>Value</th><th>Samples</th><th>Source</th>
          </tr>
        </thead>
        <tbody>
          {perf_counter_rows}
        </tbody>
      </table>
      </details>
    </section>
    <section>
      <h2>Configuration Inventory</h2>
      <p class="meta">Source: bounded, read-only AXL and CUPI configuration discovery. Counts
      reflect captured responses and do not by themselves imply policy validation.</p>
      <table>
        <thead><tr><th>Object Type</th><th>Count</th></tr></thead>
        <tbody>{configuration_summary_rows}</tbody>
      </table>
      <h3>Route Pattern Destinations</h3>
      <details><summary>Show route pattern relationships</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Pattern</th><th>Partition</th><th>Route Filter</th><th>Dial Plan</th><th>Gateway or Route List</th></tr></thead>
        <tbody>{route_pattern_rows}</tbody>
      </table></div>
      </details>
      <h3>Route List / Route Group Membership</h3>
      <details><summary>Show route list relationships</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Route List</th><th>Route Groups</th></tr></thead>
        <tbody>{route_list_rows}</tbody>
      </table></div>
      </details>
      <h3>CSS / Partition Coverage</h3>
      <details><summary>Show CSS membership coverage</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>CSS</th><th>Partitions</th><th>Count</th></tr></thead>
        <tbody>{css_coverage_rows}</tbody>
      </table></div>
      </details>
      <h3>Hunt and Directory-number Topology</h3>
      <details><summary>Show hunt, line-group, and forwarding configuration</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Type</th><th>Name/Pattern</th><th>Configuration</th></tr></thead>
        <tbody>{hunt_topology_rows}</tbody>
      </table></div></details>
      <h3>Trunk, Directory, and Device Security</h3>
      <details><summary>Show integration and security configuration</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Type</th><th>Name</th><th>Configuration</th></tr></thead>
        <tbody>{integration_security_rows}</tbody>
      </table></div></details>
      <h3>Media Resource Topology</h3>
      <details><summary>Show media-resource configuration and membership</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Type</th><th>Name</th><th>Configuration</th></tr></thead>
        <tbody>{media_topology_rows}</tbody>
      </table></div></details>
      <details>
        <summary>Show captured configuration objects</summary>
        <table>
          <thead><tr><th>Type</th><th>Name/Pattern</th><th>Details</th><th>Source</th></tr></thead>
          <tbody>{configuration_rows}</tbody>
        </table>
      </details>
    </section>
    <section>
      <h2>Certificate Validity and Trust</h2>
      <p class="meta">Source: per-node UC Certificate Management REST snapshots. Active service certificates and
      trust-store entries are presented separately: trust entries need review but do not alone establish an outage.</p>
      {certificate_summary}
      <div class="table-scroll"><table>
        <thead><tr><th>Node</th><th>Certificate</th><th>Service/Store</th><th>Kind</th>
        <th>Expires</th><th>Days</th><th>Signing</th><th>Intermediate</th><th>Root</th><th>Chain</th></tr></thead>
        <tbody>{certificate_rows}</tbody>
      </table></div>
    </section>
    <section>
      <h2>Platform Checks</h2>
      {_source_caption("Platform Checks", report)}
      <table>
        <thead><tr><th>Node</th><th>Check</th><th>Status</th><th>Details</th><th>Source</th></tr></thead>
        <tbody>
          {platform_check_rows}
        </tbody>
      </table>
    </section>
    {evidence_chapter}
    {collector_issues_section}
    {collector_notes_section}
    {collector_evidence_section}
    {reconciliation_section}
    <section>
      <h2>Detailed Device Inventory</h2>
      {_source_caption("Detailed Device Inventory", report)}
      <details>
      <summary>Show detailed configured device inventory</summary>
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Model</th><th>Protocol</th>
            <th>Device Pool</th><th>Call Manager Group</th><th>Location</th>
            <th>Region</th><th>Load</th>
          </tr>
        </thead>
        <tbody>
          {device_rows}
        </tbody>
      </table>
      </details>
    </section>
    <section>
      <h2>Detailed Device Registration</h2>
      {_source_caption("Detailed Device Registration", report)}
      <details>
      <summary>Show detailed runtime registration inventory</summary>
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Status</th><th>Registered Node</th><th>IP Address</th>
            <th>Model</th><th>Protocol</th><th>Active Load</th><th>Download Status</th><th>Failure Reason</th>
            <th>Registration Attempts</th><th>Source</th>
          </tr>
        </thead>
        <tbody>
          {registration_rows}
        </tbody>
      </table>
      </details>
    </section>
  </main>
  {template_footer}
  </div>
</body>
</html>
"""

    def _template_header(self, header_metadata: str, *, hero_image: str, logo_image: str) -> str:
        """Render the stable hero structure; themes only supply identity and art."""

        logo_markup = (
            f'<img class="rds-logo" src="{logo_image}" alt="{escape(self.template.title)}">'
            if self.theme.show_hero_logo
            else ""
        )
        return f"""
    <img class="hero-art rds-hero__art" src="{hero_image}" alt="" aria-hidden="true">
    <div class="rds-hero__overlay"></div>
    <div class="hero-copy rds-hero__content">
      {logo_markup}
      <p class="eyebrow rds-eyebrow">{escape(self.template.eyebrow)}</p>
      <h1 class="rds-title">{escape(self.template.title)}</h1>
      <p class="rds-subtitle">{escape(self.template.tagline)}</p>
    </div>
    <div class="capability-row sr-only">
      <span>Assess</span><span>Diagnose</span><span>Improve</span><span>Optimize</span>
    </div>
    <div class="header-meta rds-meta">{header_metadata}</div>"""

    @staticmethod
    def _report_transition() -> str:
        """Render the scalable, theme-tokenized transition below the hero."""

        return """
  <div class="rds-transition" aria-hidden="true">
    <svg viewBox="0 0 1200 64" preserveAspectRatio="none">
      <defs><linearGradient id="rds-transition-line" x1="0" x2="1">
        <stop stop-color="var(--rds-transition-edge)"/>
        <stop offset=".2" stop-color="var(--rds-cyan)"/>
        <stop offset=".5" stop-color="var(--rds-accent)"/>
        <stop offset=".82" stop-color="var(--rds-cyan)"/>
        <stop offset="1" stop-color="var(--rds-transition-edge)"/>
      </linearGradient></defs>
      <path d="M0 31H350c65 0 72-21 124-21h252c52 0 59 21 124 21h350"/>
      <path class="rds-transition__soft" d="M0 38h410c42 0 58 16 98 16h184c40 0 56-16 98-16h410"/>
      <circle cx="474" cy="10" r="3"/><circle cx="600" cy="10" r="4"/>
      <circle cx="726" cy="10" r="3"/>
    </svg>
  </div>"""

    @staticmethod
    def _metric_icon(kind: str) -> str:
        """Return one accessible decorative icon from the shared metric library."""

        paths = {
            "nodes": '<circle cx="6" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><path d="m8 11 8-4M8 13l8 4M18 8v8"/>',
            "devices": '<rect x="4" y="5" width="16" height="12" rx="2"/><path d="M9 21h6m-3-4v4"/>',
            "services": '<path d="M6 7h12M6 12h12M6 17h12"/><circle cx="8" cy="7" r="1"/><circle cx="16" cy="12" r="1"/><circle cx="11" cy="17" r="1"/>',
            "runtime": '<circle cx="12" cy="12" r="8"/><path d="M8 12h8m-4-4v8"/>',
            "samples": '<path d="M3 15h4l2-8 4 12 2-7h6"/>',
            "checks": '<path d="M12 3 4 7v5c0 5 3.4 8 8 9 4.6-1 8-4 8-9V7l-8-4Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/>',
            "critical": '<path d="M12 4 3 20h18L12 4Z"/><path d="M12 9v5m0 3h.01"/>',
            "warning": '<circle cx="12" cy="12" r="9"/><path d="M12 7v6m0 4h.01"/>',
            "observe": '<path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/>',
            "issues": '<path d="M5 5h14v14H5z"/><path d="m8 8 8 8m0-8-8 8"/>',
            "notes": '<path d="M5 3h11l3 3v15H5z"/><path d="M8 10h8M8 14h8M8 18h5"/>',
            "evidence": '<path d="M4 6h16v13H4z"/><path d="M8 3h8v3M8 10h8m-8 4h5"/>',
        }
        return f'<svg viewBox="0 0 24 24" aria-hidden="true">{paths[kind]}</svg>'

    def _executive_overview(
        self,
        report: AssessmentReport,
        *,
        severity_counts: Counter[FindingSeverity],
        collector_note_count: int,
        collector_issue_count: int,
        collector_evidence_count: int,
    ) -> str:
        """Render the shared functional metric groups using assessment facts."""

        groups = (
            (
                "Environment",
                "Discovered scale",
                (
                    (
                        len(report.facts.nodes),
                        "Nodes",
                        "Topology targets discovered",
                        "Discovered",
                        "nodes",
                        "normal",
                    ),
                    (
                        len(report.facts.devices),
                        "Devices",
                        "Inventory objects collected",
                        "Inventory",
                        "devices",
                        "normal",
                    ),
                    (
                        len(report.facts.services),
                        "Services",
                        "Service status records assessed",
                        "Service state",
                        "services",
                        "normal",
                    ),
                ),
            ),
            (
                "Telemetry",
                "Runtime collection",
                (
                    (
                        len(report.facts.registrations),
                        "Registrations",
                        "Runtime registration records",
                        "Runtime",
                        "runtime",
                        "normal",
                    ),
                    (
                        len(report.facts.perf_counters),
                        "Performance Samples",
                        "Performance counter samples",
                        "Sampled",
                        "samples",
                        "normal",
                    ),
                    (
                        len(report.facts.platform_checks),
                        "Health Checks Captured",
                        "Platform checks captured",
                        "Captured",
                        "checks",
                        "normal",
                    ),
                ),
            ),
            (
                "Risk signals",
                "Prioritized assessment",
                (
                    (
                        severity_counts[FindingSeverity.CRITICAL],
                        "Critical",
                        "Conditions requiring action",
                        "Action",
                        "critical",
                        "critical",
                    ),
                    (
                        severity_counts[FindingSeverity.WARNING],
                        "Warnings",
                        "Conditions requiring review",
                        "Review",
                        "warning",
                        "warning",
                    ),
                    (
                        severity_counts[FindingSeverity.INFO],
                        "Observations",
                        "Engineering context and insights",
                        "Context",
                        "observe",
                        "info",
                    ),
                ),
            ),
            (
                "Traceability",
                "Collection confidence",
                (
                    (
                        collector_issue_count,
                        "Collection Issues",
                        "Known collection gaps",
                        "Gaps",
                        "issues",
                        "warning",
                    ),
                    (
                        collector_note_count,
                        "Collection Notes",
                        "Collection and interpretation notes",
                        "Notes",
                        "notes",
                        "normal",
                    ),
                    (
                        collector_evidence_count,
                        "Evidence References",
                        "Traceable source references",
                        "Evidence",
                        "evidence",
                        "normal",
                    ),
                ),
            ),
        )
        group_markup = []
        for name, description, metrics in groups:
            cards = []
            for value, label, context, state, icon, severity in metrics:
                cards.append(
                    f"""<article class="rds-metric rds-metric--{severity}">
          <div class="rds-metric__top"><span class="rds-metric__icon">{self._metric_icon(icon)}</span><span class="rds-metric__state">{escape(state)}</span></div>
          <strong>{value}</strong><h4>{escape(label)}</h4><p>{escape(context)}</p>
        </article>"""
                )
            group_markup.append(
                f"""<div class="rds-metric-group">
      <header><span>{escape(name)}</span><p>{escape(description)}</p></header>
      <div class="rds-metric-grid">{"".join(cards)}</div>
    </div>"""
            )
        return f"""<section class="section executive-section rds-section rds-executive">
  <header class="rds-executive__heading"><span>Assessment control plane</span>
    <h2>Executive Overview</h2>
    <p>Environment scale, runtime telemetry, prioritized risk, and evidence coverage.</p>
  </header>
  <div class="rds-metric-groups">{"".join(group_markup)}</div>
</section>"""

    @staticmethod
    def _chapter_header(code: str, title: str, description: str, art: str) -> str:
        """Render one semantic chapter transition using a theme-owned art slot."""

        return f"""<div class="rds-chapter rds-chapter--{escape(art)}">
  <div class="rds-chapter__copy"><span>{escape(code)}</span><h2>{escape(title)}</h2>
    <p>{escape(description)}</p></div>
  <svg class="rds-chapter__sigil" viewBox="0 0 80 80" aria-hidden="true">
    <circle cx="40" cy="40" r="27"/><circle cx="40" cy="40" r="13"/>
    <path d="M40 3v74M3 40h74M14 14l52 52M66 14 14 66"/>
    <circle cx="40" cy="13" r="3"/><circle cx="67" cy="40" r="3"/>
  </svg>
</div>"""

    @staticmethod
    def _aletheiauc_feature_panel() -> str:
        """Provide a visual context transition without changing assessment content."""

        return """
    <section class="report-feature" aria-label="Assessment context">
      <div class="report-feature-copy">
        <p class="eyebrow">Assessment context</p>
        <h2>Evidence-led collaboration health review</h2>
        <p>Normalized facts, collection coverage, and findings follow in the sections below.
        Raw command and API detail remains in the private engineering artifact bundle.</p>
        <div class="feature-points">
          <span>Bounded collection</span><span>Evidence linked</span><span>Clear findings</span>
        </div>
      </div>
      <div class="report-feature-art" aria-hidden="true"></div>
    </section>"""

    def _template_footer(self, *, logo_image: str, footer_image: str) -> str:
        footer_label = (
            "Prepared by ComSource, Inc. · Confidential customer report"
            if self.template.key == "comsource"
            else f"AletheiaUC Assessment · {'Customer deliverable' if self.customer_safe else 'Engineering report'}"
        )
        logo_markup = (
            f'<img class="rds-logo" src="{logo_image}" alt="{escape(self.template.title)}">'
            if self.theme.show_footer_logo
            else ""
        )
        return f"""
  <footer class=\"template-footer rds-footer\" style=\"--footer-image: url('{footer_image}');\">
    {logo_markup}
    <small>{escape(footer_label)}</small>
  </footer>"""

    def _design_system_css(self) -> str:
        """Shared layout contract plus tokenized theme presentation."""

        color = self.theme.colors
        logo_panel = (
            ".comsource-report .rds-hero__content > .rds-logo, .comsource-report .rds-footer > .rds-logo { padding: 10px 14px; border-radius: 8px; background: #fff; }"
            if self.theme.key == "comsource"
            else ""
        )
        return f"""
    .rds-report {{
      --rds-page: {color["page"]};
      --rds-panel: {color["surface"]};
      --rds-text: {color["text"]};
      --rds-muted: {color["muted"]};
      --rds-accent: {color["accent"]};
      --rds-cyan: {color["cyan"]};
      --rds-gold: {color["gold"]};
      --rds-transition-edge: {color["page"]};
      width: min(1440px, calc(100% - 48px));
      margin: 24px auto 64px;
    }}
    .rds-hero {{ min-height: 360px; overflow: hidden; border-radius: 12px; background: {color["page"]}; }}
    .rds-hero__art {{ position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; object-position: {self.theme.hero_focal_point}; }}
    .rds-hero__overlay {{ position: absolute; inset: 0; background: {self.theme.hero_overlay}; }}
    .rds-hero__content {{ position: relative; z-index: 2; max-width: 760px; padding: 36px 42px 48px; }}
    .rds-logo {{ display: block; max-width: min(360px, 60vw); max-height: 96px; }}
    .rds-eyebrow {{ margin-top: 28px; }} .rds-title {{ line-height: 1.02; }}
    .rds-subtitle {{ font-size: 18px; line-height: 1.5; }}
    .rds-meta {{ position: relative; z-index: 2; }}
    .rds-transition {{ height: 64px; overflow: hidden; color: var(--rds-cyan); background: var(--rds-page); }}
    .rds-transition svg {{ display: block; width: 100%; height: 100%; }}
    .rds-transition path {{ fill: none; stroke: url(#rds-transition-line); stroke-width: 1.4; vector-effect: non-scaling-stroke; }}
    .rds-transition__soft {{ stroke: var(--rds-accent) !important; opacity: .42; }}
    .rds-transition circle {{ fill: var(--rds-gold); }}
    .rds-section {{ position: relative; overflow: hidden; border-radius: 12px; }}
    .rds-watermark::before {{ content: ""; position: absolute; right: -50px; bottom: -85px; width: 300px; height: 300px; background: var(--watermark-image) center / contain no-repeat; opacity: {self.theme.watermark_opacity}; pointer-events: none; }}
    .rds-section__heading {{ min-height: 58px; }} .rds-section__body {{ padding: 20px; }}
    .rds-executive, .rds-executive *, .rds-executive *::before, .rds-executive *::after {{ box-sizing: border-box; }}
    .rds-executive {{ width: auto; max-width: 100%; min-width: 0; overflow: hidden; text-align: left; }}
    .rds-executive > .rds-executive__heading, .rds-executive > .rds-metric-groups {{ width: 100% !important; max-width: 100% !important; min-width: 0 !important; margin-left: 0 !important; margin-right: 0 !important; transform: none !important; text-align: left !important; }}
    .rds-executive__heading {{ position: relative; z-index: 1; max-width: 720px; margin: 0 0 26px; padding: 0; overflow: visible; color: inherit; background: none; text-align: left; }}
    .rds-executive__heading::after {{ display: none; }}
    .rds-executive__heading > span {{ font: 700 10px/1.2 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .2em; text-transform: uppercase; }}
    .rds-executive__heading h2 {{ margin: 8px 0 6px; padding: 0; border: 0; background: none; font-size: clamp(26px, 3.2vw, 42px); letter-spacing: -.035em; }}
    .rds-executive__heading p {{ margin: 0; font-size: 14px; }}
    .rds-metric-groups {{ position: relative; z-index: 1; display: grid; width: 100%; min-width: 0; gap: 20px; }}
    .rds-metric-group {{ width: 100%; min-width: 0; max-width: 100%; margin: 0; padding: 0; text-align: left; }}
    .rds-metric-group > header {{ position: relative; display: flex; align-items: baseline; justify-content: flex-start; width: 100%; min-width: 0; gap: 12px; margin: 0 0 9px; padding: 0; overflow: visible; color: inherit; background: none; text-align: left; }}
    .rds-metric-group > header::after {{ display: none; }}
    .rds-metric-group > header span {{ font: 700 10px/1 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .16em; text-transform: uppercase; }}
    .rds-metric-group > header p {{ margin: 0; font-size: 11px; }}
    .rds-metric-grid {{ display: grid; width: 100%; min-width: 0; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
    .rds-metric {{ position: relative; width: 100%; min-width: 0; max-width: 100%; min-height: 154px; padding: 15px 16px 14px; overflow: hidden; border-radius: 12px; text-align: left; }}
    .rds-metric__top {{ display: flex; align-items: center; justify-content: space-between; width: 100%; min-width: 0; gap: 8px; margin-bottom: 12px; }}
    .rds-metric__icon {{ display: grid; flex: 0 0 auto; width: 30px; height: 30px; place-items: center; border-radius: 8px; }}
    .rds-metric__icon svg, .rds-recommendation__icon svg {{ width: 18px; height: 18px; fill: none; stroke: currentColor; stroke-width: 1.55; stroke-linecap: round; stroke-linejoin: round; }}
    .rds-metric__state {{ min-width: 0; max-width: calc(100% - 40px); padding: 4px 7px; overflow: hidden; border-radius: 999px; font: 700 9px/1 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .08em; text-overflow: ellipsis; text-transform: uppercase; white-space: nowrap; }}
    .rds-metric strong {{ display: block; width: 100%; margin: 0 0 2px; font-size: clamp(25px, 3vw, 38px); line-height: 1; letter-spacing: -.04em; text-align: left; overflow-wrap: anywhere; }}
    .rds-metric h4 {{ width: 100%; margin: 5px 0; font-size: 13px; line-height: 1.25; text-align: left; overflow-wrap: anywhere; }}
    .rds-metric p {{ width: 100%; margin: 0; font-size: 11px; line-height: 1.35; text-align: left; overflow-wrap: anywhere; }}
    .rds-chapter {{ position: relative; display: flex; align-items: center; min-height: 140px; margin: 42px 0 22px; overflow: hidden; border-radius: 14px; break-inside: avoid; }}
    .rds-chapter::before {{ content: ""; position: absolute; inset: 0; pointer-events: none; }}
    .rds-chapter--findings {{ background-image: var(--chapter-findings-image); }}
    .rds-chapter--scope {{ background-image: var(--chapter-scope-image); }}
    .rds-chapter--infrastructure {{ background-image: var(--chapter-infrastructure-image); }}
    .rds-chapter--analysis {{ background-image: var(--chapter-analysis-image); }}
    .rds-chapter--evidence {{ background-image: var(--chapter-evidence-image); }}
    .rds-chapter {{ background-position: center; background-size: cover; background-repeat: no-repeat; }}
    .rds-chapter__copy {{ position: relative; z-index: 1; max-width: 68%; padding: 25px 30px; }}
    .rds-chapter__copy > span {{ font: 700 10px/1 ui-monospace, SFMono-Regular, Consolas, monospace; letter-spacing: .17em; text-transform: uppercase; }}
    .rds-chapter__copy h2 {{ margin: 7px 0 5px; font-size: clamp(23px, 3vw, 34px); letter-spacing: -.03em; }}
    .rds-chapter__copy p {{ margin: 0; font-size: 12px; }}
    .rds-chapter__sigil {{ position: absolute; z-index: 1; right: 24px; width: 84px; height: 84px; fill: none; stroke-width: .75; }}
    .rds-recommendation {{ position: relative; isolation: isolate; padding: 15px 16px 15px 48px !important; overflow: hidden; border-radius: 10px; background-position: center; background-size: cover; background-repeat: no-repeat; }}
    .rds-recommendation::after {{ content: ""; position: absolute; z-index: -1; inset: 0; pointer-events: none; }}
    .rds-recommendation__icon {{ position: absolute; left: 14px; top: 13px; display: grid; width: 25px; height: 25px; place-items: center; border-radius: 7px; }}
    .rds-finding {{ display: grid; grid-template-columns: auto 1fr; gap: 12px; }}
    .rds-badge {{ align-self: start; padding: 5px 8px; border-radius: 5px; color: #fff; font-size: 11px; font-weight: 700; }}
    .rds-footer {{ min-height: 96px; background: {color["page"]} var(--footer-image) center / cover no-repeat; }}
    .rds-footer .rds-logo {{ max-width: 220px; max-height: 60px; }}
    {logo_panel}
    @media (max-width: 980px) {{ .rds-metric-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
    @media (max-width: 700px) {{ .rds-report {{ width: calc(100% - 18px); margin-top: 9px; }} .rds-hero {{ min-height: 420px; }} .rds-hero__content {{ padding: 24px 20px 38px; }} .rds-section__body {{ padding: 13px; }} .rds-chapter__copy {{ max-width: 84%; }} .rds-chapter__sigil {{ opacity: .35; }} }}
    @media (max-width: 620px) {{ .rds-executive {{ padding: 24px 18px !important; }} .rds-metric-grid {{ grid-template-columns: minmax(0, 1fr); }} .rds-metric-group > header {{ display: block; }} .rds-metric-group > header p {{ margin-top: 4px; }} }}
    @media print {{ .rds-report {{ width: 100%; margin: 0; }} .rds-hero__art, .rds-hero__overlay, .rds-watermark::before {{ display: none !important; }} .rds-hero {{ min-height: auto; }} .rds-section {{ break-inside: avoid; }} .rds-transition {{ height: 38px; }} .rds-metric {{ min-height: 118px; box-shadow: none !important; }} .rds-chapter {{ min-height: 112px; margin: 25px 0 16px; box-shadow: none !important; }} .rds-recommendation {{ background-image: none !important; }} }}
"""

    @staticmethod
    def _aletheiauc_css() -> str:
        """Beaconveil composition layer for the default AletheiaUC template."""

        return """
    body.aletheiauc-report::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: .22;
      background-image: linear-gradient(rgba(47, 124, 255, .045) 1px, transparent 1px), linear-gradient(90deg, rgba(47, 124, 255, .045) 1px, transparent 1px);
      background-size: 34px 34px;
      mask-image: linear-gradient(to bottom, black, transparent 72%);
    }
    .aletheiauc-report .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    .aletheiauc-report .report-shell { position: relative; }
    .aletheiauc-report .report-hero {
      min-height: clamp(320px, 32vw, 460px);
      padding: 0;
      background: #050812;
    }
    .aletheiauc-report .hero-art { position: absolute; z-index: 0; inset: 0; width: 100%; height: 100%; object-fit: cover; object-position: center; }
    .aletheiauc-report .hero-copy { position: absolute; z-index: 1; top: clamp(24px, 4vw, 56px); left: clamp(20px, 4vw, 56px); max-width: min(460px, calc(100% - 40px)); padding: 16px 20px; border: 1px solid rgba(106, 76, 255, .36); border-radius: 12px; background: linear-gradient(100deg, rgba(5, 8, 18, .90), rgba(5, 8, 18, .58)); box-shadow: 0 12px 30px rgba(0, 0, 0, .22); }
    .aletheiauc-report .hero-copy .eyebrow { margin: 0 0 5px; color: var(--gold); }
    .aletheiauc-report .hero-copy h1 { margin: 0; color: #fff; font-size: clamp(25px, 3.6vw, 40px); }
    .aletheiauc-report .hero-copy p:last-child { margin: 7px 0 0; color: #dce9ff; }
    .aletheiauc-report .report-hero::after {
      z-index: 3;
      inset: auto 0 0;
      width: auto;
      height: 5px;
      background: linear-gradient(90deg, #6a4cff, #22d3ee, #ffc75e);
    }
    .aletheiauc-report .rds-transition { background: linear-gradient(180deg, #02050f, #061027 52%, #02050f); }
    .aletheiauc-report .rds-transition path { filter: drop-shadow(0 0 5px rgba(39, 211, 243, .75)); }
    .aletheiauc-report .rds-transition circle { filter: drop-shadow(0 0 5px #ffc75e); }
    .aletheiauc-report .report-hero .header-meta {
      position: absolute;
      z-index: 2;
      right: clamp(20px, 4vw, 56px);
      bottom: 30px;
      left: clamp(20px, 4vw, 56px);
      justify-content: flex-start;
      max-width: none;
      margin: 0;
    }
    .aletheiauc-report .meta-chip { background: rgba(5, 8, 18, .55); backdrop-filter: blur(5px); }
    .aletheiauc-report main { display: grid; gap: 25px; }
    .aletheiauc-report main > section { margin: 0; }
    .aletheiauc-report .rds-executive {
      margin: 0;
      padding: clamp(28px, 4vw, 52px);
      border-color: rgba(59, 199, 232, .25);
      border-radius: 0 0 18px 18px;
      background: linear-gradient(90deg, rgba(2, 6, 18, .97), rgba(4, 10, 26, .88) 58%, rgba(4, 10, 26, .68)), var(--executive-image) center / cover no-repeat;
      box-shadow: inset 0 1px rgba(255, 255, 255, .04), 0 30px 80px rgba(0, 0, 0, .28);
    }
    .aletheiauc-report .rds-executive::after {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      opacity: .28;
      background-image: linear-gradient(rgba(50, 159, 206, .10) 1px, transparent 1px), linear-gradient(90deg, rgba(50, 159, 206, .10) 1px, transparent 1px);
      background-size: 32px 32px;
      mask-image: linear-gradient(90deg, #000, transparent 75%);
    }
    .aletheiauc-report .rds-executive__heading > span, .aletheiauc-report .rds-chapter__copy > span { color: var(--gold); }
    .aletheiauc-report .rds-executive__heading h2, .aletheiauc-report .rds-chapter__copy h2 { color: #eff8ff; }
    .aletheiauc-report .rds-executive__heading p, .aletheiauc-report .rds-chapter__copy p { color: #9bb5ca; }
    .aletheiauc-report .rds-metric-group > header span { color: #b89cff; }
    .aletheiauc-report .rds-metric-group > header p { color: #7894aa; }
    .aletheiauc-report .rds-metric {
      border: 1px solid rgba(67, 190, 226, .24);
      background: linear-gradient(145deg, rgba(11, 26, 52, .97), rgba(5, 11, 28, .94));
      box-shadow: inset 0 1px rgba(255, 255, 255, .035), 0 12px 30px rgba(0, 0, 0, .22);
    }
    .aletheiauc-report .rds-metric::after { content: ""; position: absolute; width: 64px; height: 64px; right: -35px; bottom: -35px; border: 1px solid rgba(140, 92, 245, .26); transform: rotate(45deg); }
    .aletheiauc-report .rds-metric__icon { color: var(--cyan); border: 1px solid rgba(39, 211, 243, .30); background: linear-gradient(145deg, rgba(39, 211, 243, .12), rgba(140, 92, 245, .15)); }
    .aletheiauc-report .rds-metric__state { color: #85a7bd; border: 1px solid rgba(119, 148, 172, .20); }
    .aletheiauc-report .rds-metric strong { color: #fff; }
    .aletheiauc-report .rds-metric h4 { color: #e8f6ff; }
    .aletheiauc-report .rds-metric p { color: #86a3b9; }
    .aletheiauc-report .rds-metric--critical { border-color: rgba(255, 89, 118, .45); }
    .aletheiauc-report .rds-metric--critical .rds-metric__icon { color: #ff607b; border-color: rgba(255, 96, 123, .34); }
    .aletheiauc-report .rds-metric--warning { border-color: rgba(255, 183, 94, .40); }
    .aletheiauc-report .rds-metric--warning .rds-metric__icon { color: var(--gold); border-color: rgba(255, 183, 94, .34); }
    .aletheiauc-report .rds-metric--info .rds-metric__icon { color: #b58aff; }
    .aletheiauc-report .rds-chapter { border: 1px solid rgba(54, 190, 229, .28); background-color: #030817; box-shadow: 0 20px 55px rgba(0, 0, 0, .27); }
    .aletheiauc-report .rds-chapter::before { background: linear-gradient(90deg, rgba(1, 4, 14, .98), rgba(2, 7, 20, .80) 48%, rgba(2, 7, 20, .14)), linear-gradient(180deg, transparent, rgba(1, 4, 14, .55)); }
    .aletheiauc-report .rds-chapter__sigil { stroke: rgba(82, 213, 241, .48); filter: drop-shadow(0 0 5px rgba(82, 213, 241, .55)); }
    .aletheiauc-report .rds-recommendation { border: 1px solid rgba(255, 183, 94, .30); background-image: linear-gradient(90deg, rgba(4, 10, 25, .97), rgba(4, 10, 25, .73)), var(--recommendation-image); }
    .aletheiauc-report .rds-recommendation::after { background: linear-gradient(90deg, rgba(3, 8, 20, .98) 0%, rgba(3, 8, 20, .87) 72%, rgba(3, 8, 20, .35)); }
    .aletheiauc-report .rds-recommendation__icon { color: #08101f; background: var(--gold); }
    .aletheiauc-report .report-feature {
      display: grid;
      grid-template-columns: minmax(0, 1.08fr) minmax(300px, .92fr);
      min-height: 300px;
      overflow: hidden;
      border-color: rgba(106, 76, 255, .38);
      background: linear-gradient(135deg, rgba(21, 31, 54, .98), rgba(8, 13, 29, .94));
    }
    .aletheiauc-report .report-feature::before { opacity: .035; background: var(--emblem-image) 8% 50% / 360px no-repeat; }
    .aletheiauc-report .report-feature-copy { position: relative; z-index: 1; margin: 0; padding: clamp(28px, 4vw, 52px); }
    .aletheiauc-report .report-feature-copy .eyebrow { color: var(--gold); }
    .aletheiauc-report .report-feature-copy h2 { margin: 8px 0 12px; padding: 0; border: 0; background: none; font-size: clamp(25px, 3vw, 34px); }
    .aletheiauc-report .report-feature-copy p { max-width: 620px; color: var(--muted); }
    .aletheiauc-report .feature-points { display: flex; flex-wrap: wrap; gap: 9px; margin-top: 22px; }
    .aletheiauc-report .feature-points span { padding: 7px 10px; border: 1px solid rgba(34, 211, 238, .27); border-radius: 999px; color: #d8fbff; background: rgba(5, 8, 18, .28); font-size: 12px; font-weight: 700; }
    .aletheiauc-report .report-feature-art { position: relative; min-height: 300px; margin: 0; background: linear-gradient(90deg, rgba(16, 24, 43, .92), transparent 32%), var(--ritual-image) center / cover no-repeat; }
    .aletheiauc-report .report-feature-art::after { content: ""; position: absolute; inset: 0; background: radial-gradient(circle at 68% 55%, rgba(255, 199, 94, .17), transparent 35%); }
    .aletheiauc-report section > h2 { margin-bottom: 0; }
    .aletheiauc-report .finding { border-left-width: 4px; }
    .aletheiauc-report th { position: sticky; top: 0; color: var(--cyan); background: #0d1528; letter-spacing: .07em; font-size: 11px; }
    @media (max-width: 900px) {
      .aletheiauc-report .report-feature { grid-template-columns: 1fr; }
      .aletheiauc-report .report-feature-art { min-height: 340px; order: -1; background: linear-gradient(180deg, transparent 58%, rgba(16, 24, 43, .9)), var(--ritual-image) center / cover no-repeat; }
    }
    @media print {
      .aletheiauc-report::before, .aletheiauc-report .report-feature-art, .aletheiauc-report .hero-art { display: none !important; }
      .aletheiauc-report .report-hero { min-height: 155px; background: #fff !important; border: 2px solid #20283a; }
      .aletheiauc-report .report-hero::before { content: "AletheiaUC Assessment"; position: absolute; left: 24px; top: 34px; color: #111; font-size: 34px; font-weight: 750; }
      .aletheiauc-report .report-hero .header-meta { right: 24px; bottom: 20px; left: 24px; }
      .aletheiauc-report .report-feature { display: block; min-height: 0; }
      .aletheiauc-report .rds-metric { background: #fff !important; color: #111 !important; box-shadow: none; }
    }"""

    @staticmethod
    def _comsource_css() -> str:
        """ComSource-only visual layer, based on the supplied branding pack."""

        return """
    body.comsource-report {
      background: #eef2f6;
      color: #20283a;
    }
    .comsource-report .report-shell {
      width: min(1450px, calc(100% - 36px));
      margin: 24px auto 60px;
      padding: 0;
    }
    .comsource-report .report-hero {
      min-height: 330px;
      padding: 34px 42px 46px;
      border-radius: 16px;
      background: linear-gradient(90deg, rgba(8, 13, 34, .97) 0%, rgba(16, 22, 51, .92) 49%, rgba(46, 29, 103, .45) 100%), var(--hero-image);
      background-position: center;
      background-size: cover;
      box-shadow: 0 18px 45px rgba(16, 22, 51, .22);
    }
    .comsource-report .report-hero::after {
      inset: auto 0 0;
      width: auto;
      height: 7px;
      background: linear-gradient(90deg, #2e1d67, #0096d6);
    }
    .comsource-report .report-hero .masthead { min-height: 0; }
    .comsource-report .logo-panel {
      display: inline-flex;
      align-items: center;
      padding: 12px 16px;
      border-radius: 10px;
      background: #fff;
      box-shadow: 0 8px 24px rgba(0, 0, 0, .18);
    }
    .comsource-report .logo-panel img { display: block; width: 265px; max-width: 55vw; height: auto; }
    .comsource-report .report-hero .eyebrow { margin-top: 30px; color: #62d4ff; }
    .comsource-report .report-hero h1 { max-width: 780px; color: #fff; font-size: clamp(34px, 5vw, 52px); }
    .comsource-report .report-hero p { color: #d9e7f5; }
    .comsource-report .report-hero .header-meta { justify-content: flex-start; max-width: 780px; margin-top: 24px; }
    .comsource-report .meta-chip { background: rgba(255, 255, 255, .08); color: #fff; }
    .comsource-report .meta-chip::before { color: #62d4ff; }
    .comsource-report .rds-transition { height: 42px; background: #eef2f6; }
    .comsource-report .rds-transition path { filter: drop-shadow(0 0 3px rgba(0, 150, 214, .35)); }
    .comsource-report main { display: grid; gap: 18px; }
    .comsource-report section {
      position: relative;
      overflow: hidden;
      margin: 0;
      border: 1px solid #d8e1ea;
      border-radius: 12px;
      background: #fff;
      box-shadow: 0 10px 28px rgba(16, 22, 51, .07);
    }
    .comsource-report section::before {
      right: -45px;
      bottom: -90px;
      left: auto;
      top: auto;
      width: 280px;
      height: 280px;
      border: 0;
      border-radius: 0;
      background: var(--watermark-image) center / contain no-repeat;
      opacity: .42;
    }
    .comsource-report section > h2 {
      position: relative;
      z-index: 1;
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 0;
      padding: 16px 20px;
      border-bottom: 1px solid #d8e1ea;
      background: linear-gradient(90deg, #f5f8fb, #fff);
      color: #2e1d67;
      font-size: 20px;
    }
    .comsource-report section > h2::before { content: \"\"; width: 5px; height: 27px; border-radius: 4px; background: linear-gradient(#2e1d67, #0096d6); }
    .comsource-report section > :not(h2) { position: relative; z-index: 1; }
    .comsource-report .summary-grid { padding: 20px; }
    .comsource-report .metric { background: #fff; border-color: #d8e1ea; border-top: 4px solid #147cc1; box-shadow: none; }
    .comsource-report .metric strong { color: #101633; }
    .comsource-report .metric span, .comsource-report .meta { color: #667085; }
    .comsource-report .rds-executive {
      padding: 32px;
      background: linear-gradient(90deg, rgba(255, 255, 255, .98), rgba(255, 255, 255, .92) 68%, rgba(255, 255, 255, .78)), var(--executive-image) center / cover no-repeat;
      box-shadow: 0 14px 36px rgba(16, 22, 51, .09);
    }
    .comsource-report .rds-executive::before { opacity: .13; }
    .comsource-report .rds-executive__heading > span, .comsource-report .rds-chapter__copy > span { color: #0096d6; }
    .comsource-report .rds-executive__heading h2 { color: #101633; }
    .comsource-report .rds-executive__heading p { color: #667085; }
    .comsource-report .rds-metric-group > header span { color: #2e1d67; }
    .comsource-report .rds-metric-group > header p { color: #667085; }
    .comsource-report .rds-metric { border: 1px solid #d8e1ea; border-top: 4px solid #147cc1; background: #fff; box-shadow: 0 8px 20px rgba(16, 22, 51, .06); }
    .comsource-report .rds-metric__icon { color: #147cc1; border: 1px solid #b9dff0; background: #eef9fd; }
    .comsource-report .rds-metric__state { color: #536679; border: 1px solid #d8e1ea; background: #f5f8fb; }
    .comsource-report .rds-metric strong, .comsource-report .rds-metric h4 { color: #101633; }
    .comsource-report .rds-metric p { color: #667085; }
    .comsource-report .rds-metric--critical { border-top-color: #b42318; }
    .comsource-report .rds-metric--critical .rds-metric__icon { color: #b42318; border-color: #f1b7b2; background: #fff4f3; }
    .comsource-report .rds-metric--warning { border-top-color: #b54708; }
    .comsource-report .rds-metric--warning .rds-metric__icon { color: #b54708; border-color: #f2c59e; background: #fff8f0; }
    .comsource-report .rds-metric--info .rds-metric__icon { color: #2e1d67; border-color: #cfc6ec; background: #f7f5fc; }
    .comsource-report .rds-chapter { margin: 0; border: 1px solid #d8e1ea; background-color: #101633; box-shadow: 0 10px 28px rgba(16, 22, 51, .10); }
    .comsource-report .rds-chapter::before { background: linear-gradient(90deg, rgba(8, 13, 34, .98), rgba(16, 22, 51, .90) 52%, rgba(46, 29, 103, .38)); }
    .comsource-report .rds-chapter__copy h2 { color: #fff; }
    .comsource-report .rds-chapter__copy p { color: #d5e2ee; }
    .comsource-report .rds-chapter__sigil { stroke: rgba(98, 212, 255, .58); }
    .comsource-report .rds-recommendation { border: 1px solid #c8d9e6; background-image: linear-gradient(90deg, rgba(245, 248, 251, .98), rgba(255, 255, 255, .93)), var(--recommendation-image); }
    .comsource-report .rds-recommendation::after { background: linear-gradient(90deg, rgba(255, 255, 255, .98), rgba(255, 255, 255, .88)); }
    .comsource-report .rds-recommendation__icon { color: #fff; background: #2e1d67; }
    .comsource-report .finding { background: #fff; border-color: #d8e1ea; }
    .comsource-report th { background: #101633; color: #fff; }
    .comsource-report th, .comsource-report td { border-bottom-color: #d8e1ea; }
    .comsource-report tbody tr:nth-child(even) { background: #f5f8fb; }
    .comsource-report .template-footer { display: flex; align-items: center; justify-content: space-between; gap: 20px; margin-top: 18px; padding: 16px 20px; border-radius: 10px; background: #080d22; color: #fff; }
    .comsource-report .footer-logo { padding: 7px 10px; border-radius: 7px; background: #fff; }
    .comsource-report .footer-logo img { display: block; width: 180px; height: auto; }
    .comsource-report .template-footer small { color: #d5e2ee; }
    @media (max-width: 700px) {
      .comsource-report .report-shell { width: calc(100% - 18px); margin-top: 9px; }
      .comsource-report .report-hero { min-height: 0; padding: 24px 20px 38px; }
      .comsource-report .template-footer { align-items: flex-start; flex-direction: column; }
    }
    @media print {
      .comsource-report, .comsource-report body { background: #fff; }
      .comsource-report .report-shell { width: 100%; margin: 0; }
      .comsource-report .report-hero { min-height: auto; border: 1px solid #aab4c1; background: #101633 !important; }
      .comsource-report .report-hero h1, .comsource-report .report-hero p { color: #fff !important; }
      .comsource-report section { break-inside: avoid; }
      .comsource-report .template-footer { border: 1px solid #cbd3dc; background: #fff; color: #20283a; }
      .comsource-report .template-footer small { color: #667085; }
    }"""

    def _header_metadata(self, report: AssessmentReport) -> str:
        """Render header chips from the actual assessment scope."""

        technologies = self._assessed_technologies(report)
        chips = [
            f'<span class="meta-chip scope">{escape(_technology_cluster_label(technology))}</span>'
            for technology in technologies
        ]
        edition = "Customer deliverable" if self.customer_safe else "Engineering edition"
        diagnostic = (
            "Diagnostic capture enabled"
            if report.runtime_metadata.get("diagnostic_capture")
            else "Baseline collection"
        )
        chips.extend(
            (
                f'<span class="meta-chip">{edition}</span>',
                f'<span class="meta-chip diagnostic">{diagnostic}</span>',
            )
        )
        return "".join(chips)

    def _assessed_technologies(self, report: AssessmentReport) -> list[str]:
        """Return unique technologies in selection order, without inventing scope."""

        technologies: list[str] = []
        targets = report.runtime_metadata.get("targets")
        if isinstance(targets, list):
            for target in targets:
                if isinstance(target, dict) and isinstance(target.get("technology"), str):
                    technologies.append(target["technology"])

        if not technologies:
            clusters = [*report.facts.clusters]
            if report.facts.cluster is not None:
                clusters.append(report.facts.cluster)
            technologies.extend(
                technology
                for cluster in clusters
                if (technology := _technology_from_product(cluster.product)) is not None
            )

        unique: list[str] = []
        for technology in technologies:
            normalized = technology.strip().lower()
            if normalized and normalized not in unique:
                unique.append(normalized)
        return unique

    def _methodology_scope_section(self, report: AssessmentReport) -> str:
        collector_names = ", ".join(
            self._collector_label(result.collector_name) for result in report.collector_results
        )
        if not collector_names:
            collector_names = display_text(None)
        collector_note_count = sum(len(result.notes) for result in report.collector_results)
        collector_issue_count = sum(
            len(result.warnings) + len(result.errors) for result in report.collector_results
        )
        collector_evidence_count = sum(len(result.evidence) for result in report.collector_results)
        sample_mode = _is_sample_report(report)
        metadata = report.runtime_metadata
        synthetic_notice = ""
        if sample_mode:
            synthetic_notice = """
      <p><strong>This report contains synthetic sample data generated by SampleCollector.</strong>
      It is intended for layout and development validation only.</p>
"""

        rows = [
            ("Report mode", "Synthetic sample" if sample_mode else "Assessment run"),
            ("Synthetic data", "Yes" if sample_mode else "No"),
            ("Collectors", collector_names),
            ("Collector count", str(len(report.collector_results))),
            ("Collector notes", str(collector_note_count)),
            ("Collector evidence refs", str(collector_evidence_count)),
            ("Collector issues", str(collector_issue_count)),
            ("Findings", str(len(report.findings))),
            ("Device inventory count", str(len(report.facts.devices))),
            ("Registration count", str(len(report.facts.registrations))),
            ("Services count", str(len(report.facts.services))),
            ("Perf counter count", str(len(report.facts.perf_counters))),
            ("Platform check count", str(len(report.facts.platform_checks))),
            (
                "Profile",
                self._identifier(display_text(metadata.get("profile_name")), "Profile"),
            ),
            (
                "Publisher",
                self._identifier(display_text(metadata.get("publisher")), "Node"),
            ),
            ("Artifacts enabled", "Yes" if metadata.get("artifacts_enabled") else "No"),
            ("Artifact redaction mode", display_text(metadata.get("artifact_redaction"))),
            (
                "TLS verification mode",
                "Enabled" if metadata.get("tls_verification") else "Disabled",
            ),
            (
                "Phone inventory scope",
                "Enabled" if metadata.get("phone_inventory_enabled") else "Skipped",
            ),
            ("Diagnostic capture", "Enabled" if metadata.get("diagnostic_capture") else "Disabled"),
            ("Customer-safe HTML", "Enabled" if self.customer_safe else "Disabled"),
        ]
        rendered_rows = "".join(
            f"<tr><th>{escape(name)}</th><td>{escape(value)}</td></tr>" for name, value in rows
        )
        return f"""
    <section>
      <h2>Assessment Methodology and Scope</h2>
      {synthetic_notice}
      <table>
        <tbody>
          {rendered_rows}
        </tbody>
      </table>
    </section>
"""

    def _coverage_section(self, report: AssessmentReport) -> str:
        rows = "\n".join(
            (
                "<tr>"
                f"<td>{escape(item.name)}</td>"
                f"<td>{escape(display_status_label(item.status))}</td>"
                f"<td>{item.count}</td>"
                f"<td>{escape(item.detail)}</td>"
                "</tr>"
            )
            for item in build_report_coverage(report)
        )
        return f"""
    <section>
      <h2>Collection Coverage</h2>
      <table>
        <thead><tr><th>Area</th><th>Status</th><th>Count</th><th>Detail</th></tr></thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </section>
"""

    def _cluster_section(self, report: AssessmentReport) -> str:
        if report.facts.cluster is None:
            return f"""
    <section>
      <h2>Cluster</h2>
      {_source_caption("Cluster", report)}
      <p>Cluster identity was not collected.</p>
    </section>
"""

        cluster = report.facts.cluster
        return f"""
    <section>
      <h2>Cluster</h2>
      {_source_caption("Cluster", report)}
      <table>
        <tbody>
          <tr><th>Cluster Anchor</th><td>{escape(self._identifier(cluster.name, "Node"))}</td></tr>
          <tr><th>Product</th><td>{escape(cluster.product)}</td></tr>
          <tr><th>Version</th><td>{escape(cluster.version)}</td></tr>
        </tbody>
      </table>
    </section>
"""

    @staticmethod
    def _node_source_caption(report: AssessmentReport) -> str:
        technologies = {node.technology for node in report.facts.nodes}
        sources = []
        if "cucm" in technologies:
            sources.append("CUCM configuration discovery")
        if "cuc" in technologies:
            sources.append("Unity Connection cluster status")
        if not sources:
            return '<p class="meta">Source: normalized assessment data.</p>'
        return f'<p class="meta">Source: {escape("; ".join(sources))}.</p>'

    def _node_rows(self, report: AssessmentReport) -> str:
        if not report.facts.nodes:
            return '<tr><td colspan="5">No nodes discovered.</td></tr>'

        nodes = sorted(
            report.facts.nodes,
            key=lambda item: (
                item.technology or "",
                item.role.strip().lower() != "publisher",
                item.name.lower(),
                item.address.lower(),
            ),
        )
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(node.technology, empty='Single cluster').upper())}</td>"
                f"<td>{escape(self._identifier(node.name, 'Node'))}</td>"
                f"<td>{escape(self._identifier(node.address, 'Address'))}</td>"
                f"<td>{escape(node.role)}</td>"
                f"<td>{escape(self._node_reachability(report, node.name, node.address, node.reachable))}</td>"
                "</tr>"
            )
            for node in nodes
        )

    @staticmethod
    def _node_reachability(
        report: AssessmentReport,
        name: str,
        address: str,
        reachable: bool | None,
    ) -> str:
        """Render direct collection success as reachability when no probe fact exists.

        A successful authenticated collection request is stronger and more useful than
        leaving a discovered node's reachability blank.  We do not infer a failure for
        nodes that were not contacted directly; that remains an unassessed state.
        """

        if reachable is not None:
            return display_bool(reachable)
        node_keys = {value.strip().casefold() for value in (name, address) if value.strip()}
        for result in report.collector_results:
            for evidence in result.evidence:
                if evidence.node and evidence.node.strip().casefold() in node_keys:
                    return "Yes (data collected)"
        return "Not assessed directly"

    def _device_rows(self, report: AssessmentReport) -> str:
        if not report.facts.devices:
            return '<tr><td colspan="8">No devices inventoried.</td></tr>'
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(device.name))}</td>"
                f"<td>{escape(display_text(device.model))}</td>"
                f"<td>{escape(display_text(device.protocol))}</td>"
                f"<td>{escape(display_text(device.device_pool))}</td>"
                f"<td>{escape(display_text(device.call_manager_group))}</td>"
                f"<td>{escape(display_text(device.location))}</td>"
                f"<td>{escape(display_text(device.region))}</td>"
                f"<td>{escape(display_text(device.configured_load))}</td>"
                "</tr>"
            )
            for device in report.facts.devices
        )

    def _device_model_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.devices:
            return '<tr><td colspan="5">No device inventory facts collected.</td></tr>'

        counts: dict[str, Counter[str]] = {}
        for device in report.facts.devices:
            model = device.model or "Unknown model"
            protocol = _protocol_bucket(device.protocol)
            counts.setdefault(model, Counter())[protocol] += 1

        rows = []
        for model in sorted(counts):
            model_counts = counts[model]
            sip_count = model_counts["SIP"]
            sccp_count = model_counts["SCCP"]
            other_count = model_counts["Other"]
            total = sip_count + sccp_count + other_count
            rows.append(
                "<tr>"
                f"<td>{escape(model)}</td>"
                f"<td>{sip_count}</td>"
                f"<td>{sccp_count}</td>"
                f"<td>{other_count}</td>"
                f"<td>{total}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _device_load_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.devices:
            return '<tr><td colspan="9">No device inventory facts collected.</td></tr>'
        if not report.facts.device_load_defaults:
            # Static overrides remain authoritative even without Device Defaults.
            default_by_key: dict[tuple[str, str], str | None] = {}
        else:
            default_by_key = {
                _model_protocol_key(default.model, default.protocol): default.default_load
                for default in report.facts.device_load_defaults
            }

        rows = []
        for key, devices in _devices_by_model_protocol(report).items():
            model, protocol = key
            default_load = default_by_key.get(key)
            overrides = [device for device in devices if device.configured_load]
            matching_count = sum(
                1 for device in overrides if _loads_equal(device.configured_load, default_load)
            )
            differing_count = sum(
                1
                for device in overrides
                if default_load and not _loads_equal(device.configured_load, default_load)
            )
            unknown_count = len(overrides) if not default_load else 0
            inherited_count = len(devices) - len(overrides)
            rows.append(
                "<tr>"
                f"<td>{escape(display_text(model))}</td>"
                f"<td>{escape(display_text(protocol))}</td>"
                f"<td>{escape(display_text(default_load))}</td>"
                f"<td>{len(devices)}</td>"
                f"<td>{len(overrides)}</td><td>{matching_count}</td>"
                f"<td>{differing_count}</td><td>{unknown_count}</td><td>{inherited_count}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _static_load_summary_rows(self, report: AssessmentReport) -> str:
        counts = Counter(
            (device.model or "Unknown model", device.protocol or "Unknown", device.configured_load)
            for device in report.facts.devices
            if device.configured_load
        )
        if not counts:
            return '<tr><td colspan="4">No static Phone Load overrides found.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(model)}</td><td>{escape(protocol)}</td>"
            f"<td>{escape(load)}</td><td>{count}</td></tr>"
            for (model, protocol, load), count in sorted(counts.items())
        )

    def _firmware_correlation_rows(self, report: AssessmentReport) -> str:
        counts = _firmware_correlation_counts(report)
        if not counts:
            return '<tr><td colspan="2">No matched configured/runtime firmware records available.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(state)}</td><td>{count}</td></tr>"
            for state, count in sorted(counts.items())
        )

    def _registration_rows(self, report: AssessmentReport) -> str:
        if not report.facts.registrations:
            return '<tr><td colspan="11">No device registration facts collected.</td></tr>'
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(registration.name))}</td>"
                f"<td>{escape(display_text(registration.status))}</td>"
                f"<td>{escape(display_text(registration.registered_node))}</td>"
                f"<td>{escape(display_text(registration.ip_address))}</td>"
                f"<td>{escape(display_text(registration.model))}</td>"
                f"<td>{escape(display_text(registration.protocol))}</td>"
                f"<td>{escape(display_text(registration.active_load))}</td>"
                f"<td>{escape(display_text(registration.download_status))}</td>"
                f"<td>{escape(display_text(registration.download_failure_reason))}</td>"
                f"<td>{escape(display_text(registration.registration_attempts))}</td>"
                f"<td>{escape(display_source(registration.source))}</td>"
                "</tr>"
            )
            for registration in report.facts.registrations
        )

    def _registration_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.registrations:
            return '<tr><td colspan="5">No device registration facts collected.</td></tr>'

        counts: dict[str, Counter[str]] = {
            "Phones": Counter(),
            "Gateways/endpoints": Counter(),
            "SIP trunks": Counter(),
        }
        for registration in report.facts.registrations:
            category = _registration_category(
                name=registration.name,
                model=registration.model,
                protocol=registration.protocol,
            )
            counts.setdefault(category, Counter())[
                _registration_status_bucket(registration.status)
            ] += 1

        rows = []
        for category in ("Phones", "Gateways/endpoints", "SIP trunks"):
            category_counts = counts[category]
            registered_count = category_counts["registered"]
            unregistered_count = category_counts["unregistered"]
            other_count = category_counts["other"]
            total = registered_count + unregistered_count + other_count
            rows.append(
                "<tr>"
                f"<td>{escape(category)}</td>"
                f"<td>{registered_count}</td>"
                f"<td>{unregistered_count}</td>"
                f"<td>{other_count}</td>"
                f"<td>{total}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _firmware_summary_rows(self, report: AssessmentReport) -> str:
        loads = Counter(
            (
                registration.model or "Unknown model",
                registration.protocol or "Unknown",
                registration.active_load or "Unavailable",
            )
            for registration in _firmware_registrations(report)
        )
        if not loads:
            return '<tr><td colspan="4">No runtime firmware data collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(model)}</td><td>{escape(protocol)}</td>"
            f"<td>{escape(load)}</td><td>{count}</td></tr>"
            for (model, protocol, load), count in sorted(loads.items())
        )

    def _firmware_failure_rows(self, report: AssessmentReport) -> str:
        failures = Counter(
            registration.download_failure_reason or "Reason unavailable"
            for registration in report.facts.registrations
            if (registration.download_status or "").strip().lower() == "failed"
        )
        if not failures:
            return '<tr><td colspan="2">No explicit firmware download failures reported.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(reason)}</td><td>{count}</td></tr>"
            for reason, count in sorted(failures.items())
        )

    def _firmware_failure_detail_rows(self, report: AssessmentReport) -> str:
        failures = Counter(
            (
                registration.model or "Unknown model",
                registration.registered_node or "Node unavailable",
                registration.download_failure_reason or "Reason unavailable",
            )
            for registration in report.facts.registrations
            if (registration.download_status or "").strip().lower() == "failed"
        )
        if not failures:
            return '<tr><td colspan="4">No explicit firmware download failures reported.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(model)}</td><td>{escape(self._identifier(node, 'Node'))}</td>"
            f"<td>{escape(reason)}</td><td>{count}</td></tr>"
            for (model, node, reason), count in sorted(failures.items())
        )

    def _mixed_firmware_rows(self, report: AssessmentReport) -> str:
        grouped: dict[tuple[str, str], Counter[str]] = {}
        for registration in _firmware_registrations(report):
            if not registration.active_load:
                continue
            key = (registration.model or "Unknown model", registration.protocol or "Unknown")
            grouped.setdefault(key, Counter())[registration.active_load] += 1
        mixed = {key: loads for key, loads in grouped.items() if len(loads) > 1}
        if not mixed:
            return '<tr><td colspan="5">No mixed active firmware populations found.</td></tr>'
        configured = Counter(
            (device.model or "Unknown model", device.protocol or "Unknown")
            for device in report.facts.devices
        )
        return "\n".join(
            f"<tr><td>{escape(model)}</td><td>{escape(protocol)}</td>"
            f"<td>{escape('; '.join(f'{load}: {count}' for load, count in sorted(loads.items())))}</td>"
            f"<td>{sum(loads.values())}</td><td>{configured[(model, protocol)]}</td></tr>"
            for (model, protocol), loads in sorted(mixed.items())
        )

    def _firmware_exception_rows(self, report: AssessmentReport) -> str:
        exceptions = _firmware_exceptions(report)
        if not exceptions:
            return '<tr><td colspan="9">No firmware exceptions found.</td></tr>'
        rows = []
        for registration, device, default_load in exceptions:
            rows.append(
                "<tr>"
                f"<td>{escape(_firmware_exception_impact(registration, device, default_load))}</td>"
                f"<td>{escape(self._identifier(registration.name, 'Device'))}</td>"
                f"<td>{escape(display_text(registration.model or device.model))}</td>"
                f"<td>{escape(display_text(device.configured_load))}</td>"
                f"<td>{escape(display_text(default_load))}</td>"
                f"<td>{escape(display_text(registration.active_load))}</td>"
                f"<td>{escape(display_text(registration.download_status))}</td>"
                f"<td>{escape(display_text(registration.download_failure_reason))}</td>"
                f"<td>{escape(self._identifier(registration.registered_node, 'Node'))}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _service_rows(self, report: AssessmentReport) -> str:
        if not report.facts.services:
            return '<tr><td colspan="8">No service status facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(self._identifier(service.node, 'Node'))}</td>"
                f"<td>{escape(service.service_name)}</td>"
                f"<td>{escape(display_text(service.service_type))}</td>"
                f"<td>{escape(display_text(service.group_name))}</td>"
                f"<td>{escape(service.status)}</td>"
                f"<td>{escape(display_duration(service.uptime_seconds))}</td>"
                f"<td>{escape(display_text(service.reason))}</td>"
                f"<td>{escape(display_source(service.source))}</td>"
                "</tr>"
            )
            for service in report.facts.services
        )

    def _service_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.services:
            return '<tr><td colspan="4">No service status facts collected.</td></tr>'
        by_node: dict[str, Counter[str]] = {}
        for service in report.facts.services:
            by_node.setdefault(service.node, Counter())[service.status.strip().lower()] += 1
        return "\n".join(
            "<tr>"
            f"<td>{escape(self._identifier(node, 'Node'))}</td>"
            f"<td>{counts['started']}</td>"
            f"<td>{counts['stopped']}</td>"
            f"<td>{sum(counts.values())}</td>"
            "</tr>"
            for node, counts in sorted(by_node.items())
        )

    def _service_reason_rows(self, report: AssessmentReport) -> str:
        reasons = Counter(
            service.reason or "Reason unavailable"
            for service in report.facts.services
            if service.status.strip().lower() != "started"
        )
        if not reasons:
            return '<tr><td colspan="2">No non-started services reported.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(reason)}</td><td>{count}</td></tr>"
            for reason, count in sorted(reasons.items())
        )

    def _service_group_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.services:
            return '<tr><td colspan="4">No service status facts collected.</td></tr>'
        by_group: dict[str, Counter[str]] = {}
        for service in report.facts.services:
            group = service.group_name or "Unclassified"
            by_group.setdefault(group, Counter())[service.status.strip().lower()] += 1
        return "\n".join(
            "<tr>"
            f"<td>{escape(group)}</td><td>{counts['started']}</td>"
            f"<td>{counts['stopped']}</td><td>{sum(counts.values())}</td>"
            "</tr>"
            for group, counts in sorted(by_group.items())
        )

    def _perf_counter_rows(self, report: AssessmentReport) -> str:
        if not report.facts.perf_counters:
            return '<tr><td colspan="7">No performance counter facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(self._identifier(counter.node, 'Node'))}</td>"
                f"<td>{escape(counter.object_name)}</td>"
                f"<td>{escape(counter.counter_name)}</td>"
                f"<td>{escape(display_text(counter.instance))}</td>"
                f"<td>{escape(display_text(counter.value))}</td>"
                f"<td>{counter.sample_count}</td>"
                f"<td>{escape(display_source(counter.source))}</td>"
                "</tr>"
            )
            for counter in report.facts.perf_counters
        )

    def _perf_summary_rows(self, report: AssessmentReport) -> str:
        preferred = {
            "% CPU Time",
            "% Mem Used",
            "% VM Used",
            "CallsActive",
            "RegisteredHardwarePhones",
        }
        counters = [
            counter
            for counter in report.facts.perf_counters
            if counter.counter_name in preferred and counter.instance in {None, "_Total"}
        ]
        if not counters:
            return (
                '<tr><td colspan="4">No selected performance summary counters collected.</td></tr>'
            )
        cpu_zero_only = _cpu_counters_are_zero_only(report)
        return "\n".join(
            "<tr>"
            f"<td>{escape(self._identifier(counter.node, 'Node'))}</td>"
            f"<td>{escape(counter.counter_name)}</td>"
            f"<td>{escape('Unavailable (zero-only snapshot)' if cpu_zero_only and counter.counter_name == '% CPU Time' else display_text(counter.value))}</td>"
            f"<td>{counter.sample_count}</td>"
            "</tr>"
            for counter in sorted(counters, key=lambda item: (item.node, item.counter_name))
        )

    def _cpu_availability_note(self, report: AssessmentReport) -> str:
        if not _cpu_counters_are_zero_only(report):
            return ""
        return (
            '<p class="meta"><strong>CPU percentage unavailable:</strong> all collected CPU '
            "percentage samples were zero. The raw counters are retained, but this report "
            "does not interpret them as actual zero utilization.</p>"
        )

    def _target_scope_section(self, report: AssessmentReport) -> str:
        targets = report.runtime_metadata.get("targets")
        if not isinstance(targets, list) or not targets:
            return ""
        rows = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            technology = display_text(target.get("technology")).upper()
            address = self._target_address(report, target)
            address = self._identifier(address, "Address")
            profile = display_text(target.get("connection_profile"))
            rows.append(
                "<tr>"
                f"<td>{escape(display_text(target.get('target_id')))}</td>"
                f"<td>{escape(technology)}</td>"
                f"<td>{escape(address)}</td><td>{escape(profile)}</td>"
                "</tr>"
            )
        return (
            "<section><h2>Assessment Targets</h2>"
            '<p class="meta">Each target uses an independent connection and credential profile.</p>'
            '<div class="table-scroll"><table><thead><tr><th>Target</th><th>Technology</th>'
            "<th>Server address</th><th>Connection Profile</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div></section>"
        )

    @staticmethod
    def _target_address(report: AssessmentReport, target: dict[object, object]) -> str:
        """Use the configured address, or the discovered publisher, for target scope."""

        configured_address = display_text(target.get("address"))
        if configured_address != "—":
            return configured_address
        target_id = str(target.get("target_id") or "").strip()
        matching_nodes = [node for node in report.facts.nodes if node.target_id == target_id]
        publisher = next(
            (node for node in matching_nodes if node.role.strip().lower() == "publisher"),
            None,
        )
        node = publisher or next(iter(matching_nodes), None)
        return display_text(node.address or node.name) if node else "—"

    def _cuc_inventory_section(self, report: AssessmentReport) -> str:
        inventory = [
            item
            for item in report.facts.configuration_objects
            if item.source.startswith("CUC.CUPI") and item.object_type.endswith("Inventory")
        ]
        if not inventory:
            return ""
        rows = "".join(
            "<tr>"
            f"<td>{escape(item.name)}</td>"
            f"<td>{escape(display_text(item.details.get('total')))}</td>"
            f"<td>{escape(display_text(item.details.get('requested_rows')))}</td>"
            f"<td>{escape(display_text(item.details.get('normalized_records')))}</td>"
            f"<td>{escape(self._cuc_inventory_coverage(item))}</td>"
            "</tr>"
            for item in sorted(inventory, key=lambda item: item.name)
        )
        return f"""
    <section class="technology-section cuc-section">
      <h2>Unity Connection Inventory</h2>
      <p class="meta">Source: bounded, read-only CUPI inventory probes. Counts are normalized
      from collection metadata; individual mailbox and contact identities are not included here.</p>
      <table>
        <thead><tr><th>Inventory</th><th>Total</th><th>Probe rows</th><th>Normalized</th>
        <th>Coverage</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
</section>
"""

    @staticmethod
    def _cuc_inventory_coverage(item: ConfigurationObjectFact) -> str:
        coverage = item.details.get("coverage")
        status = item.details.get("collection_status")
        if coverage and status:
            return f"{coverage} ({status})"
        if coverage:
            return coverage
        return (
            "Count only" if not item.details.get("normalized_records") else (status or "collected")
        )

    def _cuc_configuration_section(self, report: AssessmentReport) -> str:
        configuration = [
            item
            for item in report.facts.configuration_objects
            if item.source in {"CUC.INFORMIX.SQL"}
            or (item.source.startswith("CUC.CUPI") and not item.object_type.endswith("Inventory"))
        ]
        if not configuration:
            return ""
        counts = Counter(item.object_type.removeprefix("Cuc") for item in configuration)
        summary_rows = "".join(
            f"<tr><td>{escape(object_type)}</td><td>{count}</td></tr>"
            for object_type, count in sorted(counts.items())
        )
        repeated_schedule_counts = Counter(
            (item.object_type, item.name, tuple(sorted(item.details.items())))
            for item in configuration
            if item.object_type in {"CucSchedule", "CucScheduleSet"}
        )
        detail_items = [
            (item, 1)
            for item in configuration
            if item.object_type not in {"CucSchedule", "CucScheduleSet"}
        ]
        seen_schedule_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
        for item in configuration:
            if item.object_type not in {"CucSchedule", "CucScheduleSet"}:
                continue
            key = (item.object_type, item.name, tuple(sorted(item.details.items())))
            if key in seen_schedule_keys:
                continue
            seen_schedule_keys.add(key)
            detail_items.append((item, repeated_schedule_counts[key]))
        detail_rows = "".join(
            f"<tr><td>{escape(item.object_type.removeprefix('Cuc'))}</td>"
            f"<td>{escape(item.name)}</td><td>{occurrences}</td>"
            f"<td>{escape(display_details(item.details))}</td></tr>"
            for item, occurrences in sorted(
                detail_items, key=lambda value: (value[0].object_type, value[0].name)
            )
        )
        return f"""
    <section class="technology-section cuc-section">
      <h2>Unity Connection Configuration</h2>
      <p class="meta">Source: bounded, read-only CUPI GET requests and diagnostic-only fixed
      Informix SELECT probes. Experimental SQL-derived records are explicitly labeled. Only
      reviewed non-secret fields are normalized; mailbox identities, credentials, and message
      content are excluded.</p>
      <table><thead><tr><th>Configuration area</th><th>Records</th></tr></thead>
      <tbody>{summary_rows}</tbody></table>
      <details><summary>Show Unity Connection configuration details</summary>
      <div class="table-scroll"><table><thead><tr><th>Type</th><th>Name</th><th>Occurrences</th><th>Configuration</th></tr></thead>
      <tbody>{detail_rows}</tbody></table></div></details>
</section>
"""

    def _cuc_informix_section(self, report: AssessmentReport) -> str:
        checks = [
            item for item in report.facts.platform_checks if item.source == "CUC.INFORMIX.SQL"
        ]
        if not checks:
            return ""
        labels = {
            "cuc.sql.duplicate_extensions": "Duplicate directory extensions",
            "cuc.sql.alternate_contact_transfers": "Alternate-contact transfers",
            "cuc.sql.system_transfer_targets": "System-transfer targets",
        }
        rows = "".join(
            "<tr>"
            f"<td>{escape(labels.get(item.check_name, item.check_name))}</td>"
            f"<td>{escape(item.status)}</td>"
            f"<td>{escape(display_text(item.details.get('rows_normalized')))}</td>"
            f"<td>{escape(display_text(item.details.get('row_limit')))}</td>"
            "</tr>"
            for item in checks
        )
        return f"""
    <section class="technology-section cuc-section">
      <h2>Unity Connection Experimental SQL Validation</h2>
      <p class="meta">Diagnostic-only validation using fixed, read-only
      <code>SELECT FIRST 100</code> queries against <code>unitydirdb</code> on the publisher.
      Schema errors and timeouts are reported as collection limitations, not health failures.</p>
      <table><thead><tr><th>Probe</th><th>Status</th><th>Rows</th><th>Limit</th></tr></thead>
      <tbody>{rows}</tbody></table>
    </section>
"""

    def _cuc_platform_section(self, report: AssessmentReport) -> str:
        checks = [item for item in report.facts.platform_checks if item.source == "CUC.UCOS.CLI"]
        if not checks:
            return ""
        labels = {
            "show status": "System status",
            "utils diagnose test": "Diagnostic tests",
            "utils service list": "Services",
            "show cuc cluster status": "Cluster replication",
            "show network eth0 detail": "Ethernet 0",
            "utils core active list": "Active core files",
        }
        rows = []
        for check in checks:
            if check.check_name not in labels:
                continue
            details = check.details
            if check.check_name == "utils diagnose test":
                summary = f"{details.get('passed', '0')} passed; {details.get('failed', '0')} failed; {details.get('skipped', '0')} skipped"
            elif check.check_name == "utils service list":
                summary = f"{details.get('started', '0')} started; {details.get('stopped', '0')} stopped; {details.get('not_activated', '0')} not activated"
            elif check.check_name == "show cuc cluster status":
                primary = details.get("primary_nodes", "0")
                secondary = details.get("secondary_nodes", "0")
                health = "healthy replication connectivity observed"
                if details.get("unhealthy_states") not in {None, "0"}:
                    health = "replication state needs review"
                summary = f"{primary} primary; {secondary} secondary; {health}"
            elif check.check_name == "show network eth0 detail":
                summary = f"Link {details.get('link_status', 'unknown')}; duplicate IP {details.get('duplicate_ip', 'unknown')}"
            elif check.check_name == "show status":
                summary = (
                    f"Highest disk usage {details.get('max_disk_usage_percent', 'unknown')}%; "
                    f"uptime {details.get('uptime_days', 'unknown')} days"
                )
            else:
                summary = (
                    "No core files found"
                    if details.get("core_files") == "0"
                    else "Core files present"
                )
            rows.append(
                f"<tr><td>{escape(labels[check.check_name])}</td><td>{escape(check.status)}</td><td>{escape(summary)}</td></tr>"
            )
        if not rows:
            return ""
        return (
            '<section class="technology-section cuc-section"><h2>Unity Connection Platform Health</h2><p class="meta">Source: bounded UCOS diagnostic commands. Full output remains in the private engineering artifact bundle.</p><table><thead><tr><th>Check</th><th>Status</th><th>Summary</th></tr></thead><tbody>'
            + "".join(rows)
            + "</tbody></table></section>"
        )

    def _configuration_summary_rows(self, report: AssessmentReport) -> str:
        if not report.facts.configuration_objects:
            return '<tr><td colspan="2">No normalized configuration objects collected.</td></tr>'
        counts = Counter(item.object_type for item in report.facts.configuration_objects)
        return "\n".join(
            f"<tr><td>{escape(object_type)}</td><td>{count}</td></tr>"
            for object_type, count in sorted(counts.items())
        )

    def _route_pattern_relationship_rows(self, report: AssessmentReport) -> str:
        patterns = [
            item
            for item in report.facts.configuration_objects
            if item.object_type == "RoutePattern"
        ]
        if not patterns:
            return '<tr><td colspan="5">No route patterns collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(item.name)}</td><td>{escape(display_text(item.details.get('partition')))}</td>"
            f"<td>{escape(display_text(item.details.get('route_filter')))}</td>"
            f"<td>{escape(display_text(item.details.get('dial_plan')))}</td>"
            f"<td>{escape(display_text(item.details.get('destination'), empty='Relationship unavailable'))}</td></tr>"
            for item in sorted(
                patterns, key=lambda item: (item.name, item.details.get("partition", ""))
            )
        )

    def _route_list_relationship_rows(self, report: AssessmentReport) -> str:
        route_lists = [
            item for item in report.facts.configuration_objects if item.object_type == "RouteList"
        ]
        if not route_lists:
            return '<tr><td colspan="2">No route lists collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(item.name)}</td>"
            f"<td>{escape(display_text(item.details.get('route_groups'), empty='Relationship unavailable'))}</td></tr>"
            for item in sorted(route_lists, key=lambda item: item.name)
        )

    def _css_partition_coverage_rows(self, report: AssessmentReport) -> str:
        css_items = [
            item for item in report.facts.configuration_objects if item.object_type == "Css"
        ]
        if not css_items:
            return '<tr><td colspan="3">No calling search spaces collected.</td></tr>'
        rows = []
        for item in sorted(css_items, key=lambda item: item.name):
            partitions = item.details.get("partitions")
            count = (
                len([value for value in (partitions or "").split(",") if value.strip()])
                if partitions
                else 0
            )
            rows.append(
                f"<tr><td>{escape(item.name)}</td>"
                f"<td>{escape(display_text(partitions, empty='Membership unavailable'))}</td>"
                f"<td>{count if partitions else '—'}</td></tr>"
            )
        return "\n".join(rows)

    def _configuration_family_rows(
        self,
        report: AssessmentReport,
        object_types: set[str],
    ) -> str:
        selected = [
            item for item in report.facts.configuration_objects if item.object_type in object_types
        ]
        if not selected:
            return '<tr><td colspan="3">No matching configuration records collected.</td></tr>'
        return "".join(
            f"<tr><td>{escape(item.object_type)}</td><td>{escape(item.name)}</td>"
            f"<td>{escape(display_details(item.details))}</td></tr>"
            for item in sorted(selected, key=lambda value: (value.object_type, value.name))
        )

    def _service_deployment_rows(self, report: AssessmentReport) -> str:
        grouped: dict[tuple[str, str], dict[str, list[str]]] = {}
        for service in report.facts.services:
            key = (service.service_name, service.group_name or "Unclassified")
            state = "started" if service.status.strip().lower() == "started" else "stopped"
            grouped.setdefault(key, {"started": [], "stopped": []})[state].append(service.node)
        if not grouped:
            return '<tr><td colspan="4">No service deployment facts collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(name)}</td><td>{escape(group)}</td>"
            f"<td>{escape(', '.join(self._identifier(node, 'Node') for node in sorted(set(nodes['started']))) or '—')}</td>"
            f"<td>{escape(', '.join(self._identifier(node, 'Node') for node in sorted(set(nodes['stopped']))) or '—')}</td></tr>"
            for (name, group), nodes in sorted(grouped.items())
        )

    def _configuration_rows(self, report: AssessmentReport) -> str:
        if not report.facts.configuration_objects:
            return '<tr><td colspan="4">No normalized configuration objects collected.</td></tr>'
        return "\n".join(
            "<tr>"
            f"<td>{escape(item.object_type)}</td>"
            f"<td>{escape(item.name)}</td>"
            f"<td>{escape(display_details(item.details))}</td>"
            f"<td>{escape(display_source(item.source))}</td>"
            "</tr>"
            for item in sorted(
                report.facts.configuration_objects,
                key=lambda fact: (fact.object_type, fact.name),
            )
        )

    def _platform_check_rows(self, report: AssessmentReport) -> str:
        if not report.facts.platform_checks:
            return '<tr><td colspan="5">No platform check facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(self._identifier(check.node, 'Node'))}</td>"
                f"<td>{escape(check.check_name)}</td>"
                f"<td>{escape(check.status)}</td>"
                f"<td>{escape(display_details(check.details))}</td>"
                f"<td>{escape(display_source(check.source))}</td>"
                "</tr>"
            )
            for check in report.facts.platform_checks
        )

    def _certificate_rows(self, report: AssessmentReport) -> str:
        selected = [
            item
            for item in report.facts.certificates
            if (item.days_remaining is not None and item.days_remaining <= 60)
        ]
        if not report.facts.certificates:
            return '<tr><td colspan="10">Certificate metadata was not collected.</td></tr>'
        if not selected:
            return '<tr><td colspan="10">No expired or 60-day certificates found.</td></tr>'
        grouped: dict[object, list[CertificateFact]] = {}
        for item in selected:
            key = item.fingerprint_sha256 or (
                item.subject,
                item.serial_number,
                item.valid_until,
                item.name,
            )
            grouped.setdefault(key, []).append(item)
        return "\n".join(
            "<tr>"
            f"<td>{escape(', '.join(self._identifier(node, 'Node') for node in sorted({entry.node for entry in occurrences})))}</td>"
            f"<td>{escape(display_text(item.name))}</td>"
            f"<td>{escape(display_text(item.service or item.store))}</td>"
            f"<td>{escape(item.certificate_kind)}</td>"
            f"<td>{escape(display_text(item.valid_until))}</td>"
            f"<td>{escape(display_text(item.days_remaining))}</td>"
            f"<td>{'Self-signed' if item.self_signed else 'CA-signed' if item.self_signed is False else 'Unknown'}</td>"
            f"<td>{escape(display_text(item.intermediate))}</td>"
            f"<td>{escape(display_text(item.root))}</td>"
            f"<td>{escape(display_text(item.chain_status))}</td>"
            "</tr>"
            for occurrences in grouped.values()
            for item in occurrences[:1]
        )

    @staticmethod
    def _certificate_summary(report: AssessmentReport) -> str:
        selected = [
            item
            for item in report.facts.certificates
            if item.days_remaining is not None and item.days_remaining <= 60
        ]
        if not selected:
            return ""
        identity = [item for item in selected if item.certificate_kind == "identity"]
        trust = [item for item in selected if item.certificate_kind != "identity"]
        identity_expired = sum(
            item.days_remaining < 0 for item in identity if item.days_remaining is not None
        )
        identity_expiring = len(identity) - identity_expired
        trust_expired = sum(
            item.days_remaining < 0 for item in trust if item.days_remaining is not None
        )
        trust_expiring = len(trust) - trust_expired
        earliest = min(item.days_remaining for item in selected if item.days_remaining is not None)
        return (
            '<p class="meta"><strong>Certificate attention summary:</strong> '
            f"service certificates — {identity_expired} expired, {identity_expiring} expiring within 60 days; "
            f"trust entries — {trust_expired} expired, {trust_expiring} expiring within 60 days; "
            f"earliest expiry {earliest} days.</p>"
        )

    def _collector_issues_section(self, report: AssessmentReport) -> str:
        rows = []
        for result in report.collector_results:
            for warning in result.warnings:
                rows.append(
                    "<tr>"
                    f"<td>{escape(self._collector_label(result.collector_name))}</td>"
                    "<td>warning</td>"
                    f"<td>{escape(warning)}</td>"
                    "</tr>"
                )
            for error in result.errors:
                error_message = f"{error.exception_type}: {error.message}"
                rows.append(
                    "<tr>"
                    f"<td>{escape(self._collector_label(result.collector_name))}</td>"
                    "<td>error</td>"
                    f"<td>{escape(error_message)}</td>"
                    "</tr>"
                )
        if not rows:
            return ""

        return f"""
    <section>
      <h2>Collector Issues</h2>
      <table>
        <thead><tr><th>Collector</th><th>Type</th><th>Message</th></tr></thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
    </section>
"""

    def _collector_notes_section(self, report: AssessmentReport) -> str:
        rows = []
        for result in report.collector_results:
            for note in result.notes:
                rows.append(
                    f"<tr><td>{escape(result.collector_name)}</td><td>{escape(note)}</td></tr>"
                )

        if not rows:
            body = "<p>No collector notes recorded.</p>"
        else:
            body = f"""
      <table>
        <thead><tr><th>Collector</th><th>Note</th></tr></thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
"""

        return f"""
    <section>
      <h2>Collector Notes</h2>
      {body}
    </section>
"""

    def _collector_evidence_section(self, report: AssessmentReport) -> str:
        rows = []
        for result in report.collector_results:
            for evidence in result.evidence:
                artifact = str(evidence.artifact_path) if evidence.artifact_path else None
                if self.customer_safe:
                    artifact = None
                rows.append(
                    "<tr>"
                    f"<td>{escape(display_text(result.collector_name))}</td>"
                    f"<td>{escape(display_source(evidence.source))}</td>"
                    f"<td>{escape(display_text(evidence.operation))}</td>"
                    f"<td>{escape(self._identifier(evidence.node, 'Node'))}</td>"
                    f"<td>{escape(display_text(artifact))}</td>"
                    f"<td>{escape(display_text(evidence.confidence))}</td>"
                    f"<td>{escape(display_text(evidence.parser))}</td>"
                    "</tr>"
                )

        if not rows:
            body = "<p>No collector evidence references recorded.</p>"
        else:
            body = f"""
      <table>
        <thead>
          <tr>
            <th>Collector</th><th>Source</th><th>Operation</th><th>Node</th>
            <th>Artifact</th><th>Confidence</th><th>Parser</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows)}
        </tbody>
      </table>
"""

        return f"""
    <section>
      <h2>Collector Evidence</h2>
      {body}
    </section>
"""

    def _reconciliation_section(self, report: AssessmentReport) -> str:
        if not report.facts.registrations:
            return """
    <section>
      <h2>Inventory / Runtime Reconciliation</h2>
      <p class="meta">Unavailable: no normalized runtime registration facts were collected.</p>
    </section>
"""
        reconciliation = build_inventory_runtime_reconciliation(
            report.facts.devices,
            report.facts.registrations,
        )
        summary_rows = "".join(
            f"<tr><th>{escape(name)}</th><td>{value}</td></tr>"
            for name, value in (
                ("Configured inventory devices", reconciliation.inventory_count),
                ("Runtime registration records", reconciliation.runtime_count),
                ("Matched devices", len(reconciliation.matched_names)),
                (
                    "Inventory-only registration-capable/unclassified",
                    len(reconciliation.registration_capable_or_unclassified),
                ),
                ("Known non-runtime inventory objects", len(reconciliation.known_non_runtime)),
                ("Runtime-only devices", len(reconciliation.runtime_only)),
            )
        )
        inventory_only_rows = self._inventory_only_rows(
            reconciliation.registration_capable_or_unclassified
        )
        inventory_model_rows = self._inventory_only_summary_rows(
            reconciliation.registration_capable_or_unclassified, "model"
        )
        inventory_pool_rows = self._inventory_only_summary_rows(
            reconciliation.registration_capable_or_unclassified, "device_pool"
        )
        non_runtime_rows = self._inventory_only_rows(reconciliation.known_non_runtime)
        runtime_only_rows = self._runtime_only_rows(reconciliation.runtime_only)

        return f"""
    <section>
      <h2>Inventory / Runtime Reconciliation</h2>
      <p class="meta">Informational name-based comparison between configured inventory facts
      and runtime registration facts. Inventory-only objects are conservatively separated when
      their model is known not to register. Remaining devices are not automatically unregistered or unhealthy.
      Differences are not health findings.</p>
      <table>
        <tbody>
          {summary_rows}
        </tbody>
      </table>
      <h3>Runtime-only Devices</h3>
      <table>
        <thead><tr><th>Name</th><th>Status</th><th>Registered Node</th><th>Model</th><th>Protocol</th><th>Source</th></tr></thead>
        <tbody>
          {runtime_only_rows}
        </tbody>
      </table>
      <h3>Inventory-only Registration-capable or Unclassified Devices</h3>
      <div class="table-scroll"><table>
        <thead><tr><th>Model</th><th>Devices</th></tr></thead>
        <tbody>{inventory_model_rows}</tbody>
      </table></div>
      <div class="table-scroll"><table>
        <thead><tr><th>Device Pool</th><th>Devices</th></tr></thead>
        <tbody>{inventory_pool_rows}</tbody>
      </table></div>
      <table>
        <thead><tr><th>Name</th><th>Model</th><th>Protocol</th><th>Device Pool</th><th>Location</th><th>Source</th></tr></thead>
        <tbody>
          {inventory_only_rows}
        </tbody>
      </table>
      <h3>Known Non-runtime Inventory Objects</h3>
      <table>
        <thead><tr><th>Name</th><th>Model</th><th>Protocol</th><th>Device Pool</th><th>Location</th><th>Source</th></tr></thead>
        <tbody>{non_runtime_rows}</tbody>
      </table>
    </section>
"""

    def _runtime_only_rows(self, registrations: list[DeviceRegistrationFact]) -> str:
        if not registrations:
            return '<tr><td colspan="6">No runtime-only devices found.</td></tr>'
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(registration.name))}</td>"
                f"<td>{escape(display_text(registration.status))}</td>"
                f"<td>{escape(display_text(registration.registered_node))}</td>"
                f"<td>{escape(display_text(registration.model))}</td>"
                f"<td>{escape(display_text(registration.protocol))}</td>"
                f"<td>{escape(display_source(registration.source))}</td>"
                "</tr>"
            )
            for registration in registrations
        )

    def _inventory_only_rows(self, devices: list[DeviceInventoryFact]) -> str:
        if not devices:
            return (
                '<tr><td colspan="6">No configured devices absent from the RIS response.</td></tr>'
            )
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(device.name))}</td>"
                f"<td>{escape(display_text(device.model))}</td>"
                f"<td>{escape(display_text(device.protocol))}</td>"
                f"<td>{escape(display_text(device.device_pool))}</td>"
                f"<td>{escape(display_text(device.location))}</td>"
                f"<td>{escape(display_source(device.source))}</td>"
                "</tr>"
            )
            for device in devices
        )

    def _inventory_only_summary_rows(
        self, devices: list[DeviceInventoryFact], attribute: str
    ) -> str:
        counts = Counter(getattr(device, attribute) or "Unavailable" for device in devices)
        if not counts:
            return '<tr><td colspan="2">No inventory-only devices found.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(name)}</td><td>{count}</td></tr>"
            for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        )

    def _finding_section(self, finding: HealthFinding) -> str:
        severity = escape(finding.severity.value)
        facts = "\n".join(f"<li>{escape(fact)}</li>" for fact in finding.facts)
        recommendation = ""
        if finding.recommendation:
            escaped_recommendation = escape(finding.recommendation)
            recommendation = (
                '<p class="rds-recommendation">'
                f'<span class="rds-recommendation__icon">{self._metric_icon("checks")}</span>'
                f"<strong>Recommended next step:</strong> {escaped_recommendation}</p>"
            )
        evidence = self._evidence_list(finding)
        finding_metadata = f"Priority: {self._finding_priority_label(finding.severity)}"
        finding_metadata += f" | Severity: {severity}"

        return f"""
      <article class="finding rds-finding rds-{severity}">
        <div class="rds-badge">{severity.upper()}</div>
        <div><h3>{escape(finding.title)}</h3>
        <div class="meta">
          {finding_metadata}
        </div>
        <p><strong>Why it matters:</strong> {escape(finding.reasoning)}</p>
        <p><strong>What we found:</strong></p>
        <ul class="facts">
          {facts}
        </ul>
        {evidence}
        {recommendation}</div>
      </article>
"""

    def _evidence_list(self, finding: HealthFinding) -> str:
        if not finding.evidence:
            return ""

        items = []
        for evidence in finding.evidence:
            node_value = self._identifier(evidence.node, "Node")
            node = f" | Node: {escape(node_value)}" if evidence.node else ""
            artifact = ""
            if evidence.artifact_path and not self.customer_safe:
                artifact = f" | Artifact: {escape(str(evidence.artifact_path))}"
            items.append(
                "<li>"
                f"Source: {escape(display_source(evidence.source))} | "
                f"Operation: {escape(evidence.operation)}"
                f"{node}{artifact} | "
                f"Confidence: {escape(evidence.confidence)}"
                "</li>"
            )

        return f"""
        <details class="finding-evidence">
          <summary>Technical collection detail</summary>
          <ul class="facts">
            {"".join(items)}
          </ul>
        </details>
"""

    @staticmethod
    def _finding_priority_label(severity: FindingSeverity) -> str:
        if severity == FindingSeverity.CRITICAL:
            return "Action required"
        if severity == FindingSeverity.WARNING:
            return "Attention recommended"
        return "For awareness"

    def _identifier(self, value: object | None, kind: str) -> str:
        del kind
        return display_text(value)

    def _collector_label(self, name: str) -> str:
        """Render the collector label consistently in both report editions."""

        return name


def _protocol_bucket(protocol: str | None) -> str:
    normalized_protocol = (protocol or "").strip().upper()
    if normalized_protocol == "SIP":
        return "SIP"
    if normalized_protocol == "SCCP":
        return "SCCP"
    return "Other"


def _registration_status_bucket(status: str) -> str:
    normalized_status = status.strip().lower()
    if normalized_status in {"registered", "registered/matched"}:
        return "registered"
    if normalized_status in {"unregistered", "rejected", "unknown", "not_found"}:
        return "unregistered"
    return "other"


def _registration_category(name: str, model: str | None, protocol: str | None) -> str:
    normalized_name = name.strip().lower()
    normalized_model = (model or "").strip().lower()
    normalized_protocol = (protocol or "").strip().lower()
    combined = f"{normalized_name} {normalized_model} {normalized_protocol}"

    if "trunk" in combined:
        return "SIP trunks"
    if normalized_protocol in {"h323", "h.323", "mgcp", "sccp gateway"}:
        return "Gateways/endpoints"
    if any(token in combined for token in ("gateway", "vg", "cube", "h323", "mgcp")):
        return "Gateways/endpoints"
    return "Phones"


def _devices_by_model_protocol(
    report: AssessmentReport,
) -> dict[tuple[str, str], list[DeviceInventoryFact]]:
    grouped: dict[tuple[str, str], list[DeviceInventoryFact]] = {}
    for device in report.facts.devices:
        grouped.setdefault(
            _model_protocol_key(device.model, device.protocol),
            [],
        ).append(device)
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def _model_protocol_key(model: str | None, protocol: str | None) -> tuple[str, str]:
    return (model or "Unknown model", protocol or "")


def _loads_equal(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().lower() == right.strip().lower())


def _firmware_correlation_counts(report: AssessmentReport) -> Counter[str]:
    devices = {device.name.strip().lower(): device for device in report.facts.devices}
    defaults = {
        (
            (default.model or "").strip().lower(),
            (default.protocol or "").strip().lower(),
        ): default.default_load
        for default in report.facts.device_load_defaults
    }
    counts: Counter[str] = Counter()
    for registration in _firmware_registrations(report):
        device = devices.get(registration.name.strip().lower())
        if not device:
            continue
        active = registration.active_load
        override = device.configured_load
        default = defaults.get(
            ((device.model or "").strip().lower(), (device.protocol or "").strip().lower())
        )
        intended = override or default
        failed = (registration.download_status or "").strip().lower() == "failed"
        if failed and _loads_equal(active, intended):
            counts["Download failure reported; active load matches intended load"] += 1
        elif failed:
            counts["Download failed; active load differs from intended load"] += 1
        elif not active:
            counts["Runtime active load unavailable"] += 1
        elif override and _loads_equal(active, override):
            counts["Active load matches static override"] += 1
        elif override and _loads_equal(active, default):
            counts["Static override configured; active load matches current default"] += 1
        elif override:
            counts["Active load differs from static override and current default"] += 1
        elif default and _loads_equal(active, default):
            counts["Inherited active load matches current default"] += 1
        elif default:
            counts["Inherited active load differs from current default"] += 1
        else:
            counts["Active load present; current default unavailable"] += 1
    return counts


def _firmware_registrations(report: AssessmentReport) -> list[DeviceRegistrationFact]:
    """Return runtime records with evidence that firmware applies to the device."""

    devices = {device.name.strip().lower(): device for device in report.facts.devices}
    default_keys = {
        ((item.model or "").strip().lower(), (item.protocol or "").strip().lower())
        for item in report.facts.device_load_defaults
        if item.default_load
    }
    return [
        registration
        for registration in report.facts.registrations
        if registration.active_load
        or (registration.download_status or "").strip().lower() == "failed"
        or (
            (device := devices.get(registration.name.strip().lower())) is not None
            and (
                bool(device.configured_load)
                or (
                    (device.model or "").strip().lower(),
                    (device.protocol or "").strip().lower(),
                )
                in default_keys
            )
        )
    ]


def _firmware_exceptions(
    report: AssessmentReport,
) -> list[tuple[DeviceRegistrationFact, DeviceInventoryFact, str | None]]:
    devices = {device.name.strip().lower(): device for device in report.facts.devices}
    defaults = {
        (
            (item.model or "").strip().lower(),
            (item.protocol or "").strip().lower(),
        ): item.default_load
        for item in report.facts.device_load_defaults
    }
    exceptions = []
    for registration in _firmware_registrations(report):
        device = devices.get(registration.name.strip().lower())
        if device is None:
            continue
        default = defaults.get(
            ((device.model or "").strip().lower(), (device.protocol or "").strip().lower())
        )
        intended = device.configured_load or default
        failed = (registration.download_status or "").strip().lower() == "failed"
        if failed or (
            registration.active_load
            and intended
            and not _loads_equal(registration.active_load, intended)
        ):
            exceptions.append((registration, device, default))
    return exceptions


def _firmware_exception_impact(
    registration: DeviceRegistrationFact,
    device: DeviceInventoryFact,
    default_load: str | None,
) -> str:
    intended = device.configured_load or default_load
    if _loads_equal(registration.active_load, intended):
        return "Download failure recorded, but active firmware matches the intended load; review if the status persists."
    return "Firmware differs from the intended load after a failed download; investigate TFTP and the assigned firmware."


def _is_sample_report(report: AssessmentReport) -> bool:
    return any(result.collector_name == "sample" for result in report.collector_results)


def _technology_cluster_label(technology: str) -> str:
    labels = {
        "cucm": "CUCM Cluster",
        "cuc": "CUC Cluster",
        "cer": "CER Cluster",
        "imp": "IM&P Cluster",
    }
    return labels.get(technology.strip().lower(), f"{technology.strip().upper()} Cluster")


def _technology_from_product(product: str) -> str | None:
    normalized = product.lower()
    if "unity connection" in normalized:
        return "cuc"
    if "emergency responder" in normalized:
        return "cer"
    if "im and presence" in normalized or "im&p" in normalized:
        return "imp"
    if "callmanager" in normalized or "unified communications manager" in normalized:
        return "cucm"
    return None


def _cpu_counters_are_zero_only(report: AssessmentReport) -> bool:
    cpu_values = [
        counter.value
        for counter in report.facts.perf_counters
        if counter.counter_name == "% CPU Time"
    ]
    if not cpu_values:
        return False
    numeric_values = [value for value in cpu_values if isinstance(value, int | float)]
    return len(numeric_values) == len(cpu_values) and all(value == 0 for value in numeric_values)


def _has_axl_evidence(report: AssessmentReport) -> bool:
    return any(
        evidence.source.upper() == "AXL"
        for result in report.collector_results
        for evidence in result.evidence
    )


def _source_caption(section_name: str, report: AssessmentReport) -> str:
    if _is_sample_report(report):
        return '<p class="meta">Source: SampleCollector synthetic fixture data.</p>'

    inventory_caption = "Source: AXL listPhone summary inventory."
    detailed_inventory_caption = "Source: AXL listPhone summary inventory."
    if any("AXL.listDevicePool" in device.source for device in report.facts.devices):
        inventory_caption = (
            "Source: AXL listPhone summary inventory enriched by AXL listDevicePool."
        )
        detailed_inventory_caption = (
            "Source: AXL listPhone summary inventory enriched by AXL listDevicePool."
        )

    axl_sections = {
        "Cluster": "Source: AXL getCCMVersion and listProcessNode.",
        "Discovered Nodes": "Source: AXL listProcessNode.",
        "Device Inventory By Model": inventory_caption,
        "Device Load Summary": "Source: AXL phone inventory and bounded Device Defaults SQL.",
        "Detailed Device Inventory": detailed_inventory_caption,
    }
    registration_caption = "Source: RISPort70 SelectCmDeviceExt normalized runtime records."
    if any(
        registration.source == "RISPort70.selectCmDevice"
        for registration in report.facts.registrations
    ):
        registration_caption = (
            "Source: RISPort70 SelectCmDeviceExt phone detail and SelectCmDevice "
            "all-device-class runtime records."
        )
    collected_sections = {
        "Device Registration Summary": registration_caption,
        "Detailed Device Registration": registration_caption,
        "Services": "Source: Control Center Services normalized service records.",
        "Performance Counters": "Source: PerfMon normalized performance-counter records.",
        "Platform Checks": "Source: SSH/CLI fallback. Real collector not implemented yet.",
    }
    if section_name in axl_sections and _has_axl_evidence(report):
        return f'<p class="meta">{escape(axl_sections[section_name])}</p>'
    caption = collected_sections.get(section_name, "Source: Not recorded.")
    return f'<p class="meta">{escape(caption)}</p>'
