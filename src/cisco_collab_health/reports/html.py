"""Styled HTML report builder."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from html import escape

from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import CertificateFact, DeviceInventoryFact, DeviceRegistrationFact
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


class HtmlReportBuilder:
    """Builds a styled standalone HTML report."""

    def __init__(self, *, customer_safe: bool = False) -> None:
        self.customer_safe = customer_safe

    def build(self, report: AssessmentReport) -> str:
        severity_counts = Counter(finding.severity for finding in report.findings)
        collector_note_count = sum(len(result.notes) for result in report.collector_results)
        collector_issue_count = sum(
            len(result.warnings) + len(result.errors) for result in report.collector_results
        )
        collector_evidence_count = sum(
            len(result.evidence) for result in report.collector_results
        )
        methodology_scope_section = self._methodology_scope_section(report)
        cluster_section = self._cluster_section(report)
        node_rows = self._node_rows(report)
        device_rows = self._device_rows(report)
        device_model_rows = self._device_model_summary_rows(report)
        device_load_rows = self._device_load_summary_rows(report)
        device_load_note = (
            '<p class="meta">Device load defaults were unavailable; static overrides remain '
            'identifiable, but default comparison is unavailable.</p>'
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
        service_deployment_rows = self._service_deployment_rows(report)
        configuration_rows = self._configuration_rows(report)
        platform_check_rows = self._platform_check_rows(report)
        certificate_rows = self._certificate_rows(report)
        collector_issues_section = self._collector_issues_section(report)
        collector_notes_section = self._collector_notes_section(report)
        collector_evidence_section = self._collector_evidence_section(report)
        finding_sections = "\n".join(
            self._finding_section(finding) for finding in report.findings
        )
        if not finding_sections:
            finding_sections = "<p>No findings generated.</p>"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AletheiaUC Assessment</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f6fb;
      --panel: #ffffff;
      --text: #101a2d;
      --muted: #526079;
      --line: #d7ddee;
      --critical: #b42318;
      --warning: #b54708;
      --info: #2f7cff;
    }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: linear-gradient(120deg, #0a0f1e, #172554 68%, #302166);
      color: white;
      padding: 28px 32px;
    }}
    header h1 {{
      margin: 0 0 8px;
      font-size: 28px;
    }}
    header p {{
      margin: 0;
      color: #cdd9ff;
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
      border-radius: 12px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.05);
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
      background: linear-gradient(145deg, #ffffff, #f5f8ff);
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
    .meta {{
      color: var(--muted);
      font-size: 14px;
      margin-bottom: 12px;
    }}
    .facts {{
      margin: 8px 0 0;
      padding-left: 20px;
    }}
  </style>
</head>
<body>
  <header>
    <h1>AletheiaUC Assessment</h1>
    <p>Cisco Collaboration Health Assessment report</p>
  </header>
  <main>
    <section>
      <h2>Executive Overview</h2>
      <div class="summary-grid">
        <div class="metric"><strong>{len(report.facts.nodes)}</strong><span>Nodes</span></div>
        <div class="metric"><strong>{len(report.facts.devices)}</strong><span>Devices</span></div>
        <div class="metric"><strong>{len(report.facts.registrations)}</strong>
          <span>Registrations</span></div>
        <div class="metric"><strong>{len(report.facts.services)}</strong><span>Services</span></div>
        <div class="metric"><strong>{len(report.facts.perf_counters)}</strong>
          <span>Perf Counters</span></div>
        <div class="metric"><strong>{len(report.facts.platform_checks)}</strong>
          <span>Platform Checks</span></div>
        <div class="metric"><strong>{severity_counts[FindingSeverity.CRITICAL]}</strong>
          <span>Critical</span></div>
        <div class="metric"><strong>{severity_counts[FindingSeverity.WARNING]}</strong>
          <span>Warnings</span></div>
        <div class="metric"><strong>{severity_counts[FindingSeverity.INFO]}</strong>
          <span>Informational</span></div>
        <div class="metric"><strong>{collector_note_count}</strong><span>Collector Notes</span></div>
        <div class="metric"><strong>{collector_issue_count}</strong><span>Collector Issues</span></div>
        <div class="metric"><strong>{collector_evidence_count}</strong><span>API Evidence</span></div>
      </div>
    </section>
    {methodology_scope_section}
    {coverage_section}
    {cluster_section}
    <section>
      <h2>Discovered Nodes</h2>
      {_source_caption("Discovered Nodes", report)}
      <table>
        <thead><tr><th>Name</th><th>Address</th><th>Role</th><th>Reachable</th></tr></thead>
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
        <thead><tr><th>Impact</th><th>Device</th><th>Model</th><th>Static Load</th><th>Default Load</th>
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
      <p class="meta">Source: bounded AXL configuration discovery. Counts reflect captured
      list responses and do not imply dependency or policy validation.</p>
      <table>
        <thead><tr><th>Object Type</th><th>Count</th></tr></thead>
        <tbody>{configuration_summary_rows}</tbody>
      </table>
      <h3>Route Pattern Destinations</h3>
      <details><summary>Show route pattern relationships</summary>
      <div class="table-scroll"><table>
        <thead><tr><th>Pattern</th><th>Partition</th><th>Gateway or Route List</th></tr></thead>
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
      <p class="meta">Source: per-node UC Certificate Management REST snapshots. Detail is limited to expired,
      60-day expiry-window, and mandatory phone trust-store certificates.</p>
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
    {collector_issues_section}
    {collector_notes_section}
    {collector_evidence_section}
    {reconciliation_section}
    <section>
      <h2>Findings</h2>
      {finding_sections}
    </section>
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
</body>
</html>
"""

    def _methodology_scope_section(self, report: AssessmentReport) -> str:
        collector_names = ", ".join(result.collector_name for result in report.collector_results)
        if not collector_names:
            collector_names = display_text(None)
        collector_note_count = sum(len(result.notes) for result in report.collector_results)
        collector_issue_count = sum(
            len(result.warnings) + len(result.errors) for result in report.collector_results
        )
        collector_evidence_count = sum(
            len(result.evidence) for result in report.collector_results
        )
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
            ("TLS verification mode", "Enabled" if metadata.get("tls_verification") else "Disabled"),
            ("Phone inventory scope", "Enabled" if metadata.get("phone_inventory_enabled") else "Skipped"),
            ("Diagnostic capture", "Enabled" if metadata.get("diagnostic_capture") else "Disabled"),
            ("Customer-safe HTML", "Enabled" if self.customer_safe else "Disabled"),
        ]
        rendered_rows = "".join(
            f"<tr><th>{escape(name)}</th><td>{escape(value)}</td></tr>"
            for name, value in rows
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

    def _node_rows(self, report: AssessmentReport) -> str:
        if not report.facts.nodes:
            return '<tr><td colspan="4">No nodes discovered.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(self._identifier(node.name, 'Node'))}</td>"
                f"<td>{escape(self._identifier(node.address, 'Address'))}</td>"
                f"<td>{escape(node.role)}</td>"
                f"<td>{escape(display_bool(node.reachable))}</td>"
                "</tr>"
            )
            for node in report.facts.nodes
        )

    def _device_rows(self, report: AssessmentReport) -> str:
        if not report.facts.devices:
            return '<tr><td colspan="8">No devices inventoried.</td></tr>'
        if self.customer_safe:
            return '<tr><td colspan="8">Detailed device identifiers omitted from customer-safe report.</td></tr>'

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
            matching_count = sum(1 for device in overrides if _loads_equal(device.configured_load, default_load))
            differing_count = sum(1 for device in overrides if default_load and not _loads_equal(device.configured_load, default_load))
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
            for device in report.facts.devices if device.configured_load
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
        if self.customer_safe:
            return '<tr><td colspan="11">Detailed runtime identifiers omitted from customer-safe report.</td></tr>'

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
            counts.setdefault(category, Counter())[_registration_status_bucket(registration.status)] += 1

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
            counter for counter in report.facts.perf_counters
            if counter.counter_name in preferred and counter.instance in {None, "_Total"}
        ]
        if not counters:
            return '<tr><td colspan="4">No selected performance summary counters collected.</td></tr>'
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
            'percentage samples were zero. The raw counters are retained, but this report '
            'does not interpret them as actual zero utilization.</p>'
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
        if self.customer_safe:
            return '<tr><td colspan="3">Dial-plan names omitted from customer-safe report.</td></tr>'
        patterns = [item for item in report.facts.configuration_objects if item.object_type == "RoutePattern"]
        if not patterns:
            return '<tr><td colspan="3">No route patterns collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(item.name)}</td><td>{escape(display_text(item.details.get('partition')))}</td>"
            f"<td>{escape(display_text(item.details.get('destination'), empty='Relationship unavailable'))}</td></tr>"
            for item in sorted(patterns, key=lambda item: (item.name, item.details.get("partition", "")))
        )

    def _route_list_relationship_rows(self, report: AssessmentReport) -> str:
        if self.customer_safe:
            return '<tr><td colspan="2">Route-list names omitted from customer-safe report.</td></tr>'
        route_lists = [item for item in report.facts.configuration_objects if item.object_type == "RouteList"]
        if not route_lists:
            return '<tr><td colspan="2">No route lists collected.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(item.name)}</td>"
            f"<td>{escape(display_text(item.details.get('route_groups'), empty='Relationship unavailable'))}</td></tr>"
            for item in sorted(route_lists, key=lambda item: item.name)
        )

    def _css_partition_coverage_rows(self, report: AssessmentReport) -> str:
        if self.customer_safe:
            return '<tr><td colspan="3">CSS and partition names omitted from customer-safe report.</td></tr>'
        css_items = [item for item in report.facts.configuration_objects if item.object_type == "Css"]
        if not css_items:
            return '<tr><td colspan="3">No calling search spaces collected.</td></tr>'
        rows = []
        for item in sorted(css_items, key=lambda item: item.name):
            partitions = item.details.get("partitions")
            count = len([value for value in (partitions or "").split(",") if value.strip()]) if partitions else 0
            rows.append(
                f"<tr><td>{escape(item.name)}</td>"
                f"<td>{escape(display_text(partitions, empty='Membership unavailable'))}</td>"
                f"<td>{count if partitions else '—'}</td></tr>"
            )
        return "\n".join(rows)

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
        if self.customer_safe:
            return '<tr><td colspan="4">Configuration names and details omitted from customer-safe report.</td></tr>'
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
        mandatory = ("phone-sast-trust", "phone-vpn-trust")
        selected = [
            item for item in report.facts.certificates
            if (item.days_remaining is not None and item.days_remaining <= 60)
            or any(name in " ".join(filter(None, (item.name, item.store, item.service))).lower() for name in mandatory)
        ]
        if not report.facts.certificates:
            return '<tr><td colspan="10">Certificate metadata was not collected.</td></tr>'
        if not selected:
            return '<tr><td colspan="10">No expired or 60-day certificates found; mandatory phone trust stores were not returned.</td></tr>'
        grouped: dict[object, list[CertificateFact]] = {}
        for item in selected:
            key = item.fingerprint_sha256 or (item.subject, item.serial_number, item.valid_until, item.name)
            grouped.setdefault(key, []).append(item)
        return "\n".join(
            "<tr>"
            f"<td>{escape(', '.join(self._identifier(node, 'Node') for node in sorted({entry.node for entry in occurrences})))}</td>"
            f"<td>{escape('Certificate' if self.customer_safe else display_text(item.name))}</td>"
            f"<td>{escape(display_text(item.service or item.store))}</td>"
            f"<td>{escape(item.certificate_kind)}</td>"
            f"<td>{escape(display_text(item.valid_until))}</td>"
            f"<td>{escape(display_text(item.days_remaining))}</td>"
            f"<td>{'Self-signed' if item.self_signed else 'CA-signed' if item.self_signed is False else 'Unknown'}</td>"
            f"<td>{escape('Omitted' if self.customer_safe and item.intermediate else display_text(item.intermediate))}</td>"
            f"<td>{escape('Omitted' if self.customer_safe and item.root else display_text(item.root))}</td>"
            f"<td>{escape(display_text(item.chain_status))}</td>"
            "</tr>"
            for occurrences in grouped.values()
            for item in occurrences[:1]
        )

    def _collector_issues_section(self, report: AssessmentReport) -> str:
        rows = []
        for result in report.collector_results:
            for warning in result.warnings:
                message = (
                    "Warning detail omitted from customer-safe report."
                    if self.customer_safe
                    else warning
                )
                rows.append(
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
                    "<td>warning</td>"
                    f"<td>{escape(message)}</td>"
                    "</tr>"
                )
            for error in result.errors:
                error_message = (
                    "Error detail omitted from customer-safe report."
                    if self.customer_safe
                    else f"{error.exception_type}: {error.message}"
                )
                rows.append(
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
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
                note_text = (
                    "Operational note detail omitted from customer-safe report."
                    if self.customer_safe
                    else note
                )
                rows.append(
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
                    f"<td>{escape(note_text)}</td>"
                    "</tr>"
                )

        if not rows:
            body = '<p>No collector notes recorded.</p>'
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
            body = '<p>No collector evidence references recorded.</p>'
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
                ("Inventory-only registration-capable/unclassified", len(reconciliation.registration_capable_or_unclassified)),
                ("Known non-runtime inventory objects", len(reconciliation.known_non_runtime)),
                ("Runtime-only devices", len(reconciliation.runtime_only)),
            )
        )
        inventory_only_rows = self._inventory_only_rows(reconciliation.registration_capable_or_unclassified)
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
        if self.customer_safe:
            return '<tr><td colspan="6">Runtime-only identifiers omitted from customer-safe report.</td></tr>'
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
            return '<tr><td colspan="6">No configured devices absent from the RIS response.</td></tr>'
        if self.customer_safe:
            return '<tr><td colspan="6">Inventory-only identifiers omitted from customer-safe report.</td></tr>'
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
        if self.customer_safe and attribute == "device_pool":
            return '<tr><td colspan="2">Device-pool names omitted from customer-safe report.</td></tr>'
        counts = Counter(getattr(device, attribute) or "Unavailable" for device in devices)
        if not counts:
            return '<tr><td colspan="2">No inventory-only devices found.</td></tr>'
        return "\n".join(
            f"<tr><td>{escape(name)}</td><td>{count}</td></tr>"
            for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        )

    def _finding_section(self, finding: HealthFinding) -> str:
        severity = escape(finding.severity.value)
        facts = (
            "<li>Detailed facts omitted from customer-safe report.</li>"
            if self.customer_safe
            else "\n".join(f"<li>{escape(fact)}</li>" for fact in finding.facts)
        )
        recommendation = ""
        if finding.recommendation:
            escaped_recommendation = escape(finding.recommendation)
            recommendation = (
                f"<p><strong>Recommendation:</strong> {escaped_recommendation}</p>"
            )
        evidence = self._evidence_list(finding)

        return f"""
      <article class="finding {severity}">
        <h3>{escape(finding.title)}</h3>
        <div class="meta">
          Rule: {escape(finding.rule_id)} |
          Severity: {severity} |
          Type: {escape(finding.recommendation_kind.value)}
        </div>
        <p><strong>Reasoning:</strong> {escape(finding.reasoning)}</p>
        <p><strong>Facts:</strong></p>
        <ul class="facts">
          {facts}
        </ul>
        {evidence}
        {recommendation}
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
        <p><strong>Evidence:</strong></p>
        <ul class="facts">
          {"".join(items)}
        </ul>
"""

    def _identifier(self, value: object | None, kind: str) -> str:
        text = display_text(value)
        if not self.customer_safe or text == "—":
            return text
        digest = sha256(f"{kind}:{text}".encode()).hexdigest()[:8].upper()
        return f"{kind}-{digest}"


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
                ) in default_keys
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
        if failed or (registration.active_load and intended and not _loads_equal(registration.active_load, intended)):
            exceptions.append((registration, device, default))
    return exceptions


def _firmware_exception_impact(
    registration: DeviceRegistrationFact,
    device: DeviceInventoryFact,
    default_load: str | None,
) -> str:
    intended = device.configured_load or default_load
    if _loads_equal(registration.active_load, intended):
        return "Failure status; intended load active"
    return "Failed transition; intended load not active"


def _is_sample_report(report: AssessmentReport) -> bool:
    return any(result.collector_name == "sample" for result in report.collector_results)


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
    collected_sections = {
        "Device Registration Summary": "Source: RISPort70 SelectCmDeviceExt normalized runtime records.",
        "Detailed Device Registration": "Source: RISPort70 SelectCmDeviceExt normalized runtime records.",
        "Services": "Source: Control Center Services normalized service records.",
        "Performance Counters": "Source: PerfMon normalized performance-counter records.",
        "Platform Checks": "Source: SSH/CLI fallback. Real collector not implemented yet.",
    }
    if section_name in axl_sections and _has_axl_evidence(report):
        return f'<p class="meta">{escape(axl_sections[section_name])}</p>'
    caption = collected_sections.get(section_name, "Source: Not recorded.")
    return f'<p class="meta">{escape(caption)}</p>'
