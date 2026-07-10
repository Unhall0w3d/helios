"""Styled HTML report builder."""

from __future__ import annotations

from collections import Counter
from html import escape

from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.facts import DeviceInventoryFact, DeviceRegistrationFact
from cisco_collab_health.models.findings import FindingSeverity, HealthFinding
from cisco_collab_health.reports.coverage import build_report_coverage
from cisco_collab_health.reports.formatting import (
    display_bool,
    display_details,
    display_status_label,
    display_text,
)
from cisco_collab_health.reports.reconciliation import (
    build_inventory_runtime_reconciliation,
)


class HtmlReportBuilder:
    """Builds a styled standalone HTML report."""

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
        coverage_section = self._coverage_section(report)
        registration_rows = self._registration_rows(report)
        registration_summary_rows = self._registration_summary_rows(report)
        reconciliation_section = self._reconciliation_section(report)
        service_rows = self._service_rows(report)
        perf_counter_rows = self._perf_counter_rows(report)
        platform_check_rows = self._platform_check_rows(report)
        collector_issues_section = self._collector_issues_section(report)
        collector_notes_section = self._collector_notes_section(report)
        collector_evidence_section = self._collector_evidence_section(report)
        finding_sections = "\n".join(self._finding_section(finding) for finding in report.findings)
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
      <table>
        <thead>
          <tr>
            <th>Model</th><th>Protocol</th><th>Default Load</th>
            <th>Devices</th><th>Manual Loads</th><th>Missing Loads</th><th>Unknown Default</th>
          </tr>
        </thead>
        <tbody>
          {device_load_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Services</h2>
      {_source_caption("Services", report)}
      <table>
        <thead>
          <tr>
            <th>Node</th><th>Service</th><th>Activated</th><th>Status</th>
            <th>Uptime Seconds</th><th>Source</th>
          </tr>
        </thead>
        <tbody>
          {service_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Performance Counters</h2>
      {_source_caption("Performance Counters", report)}
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
    </section>
    <section>
      <h2>Detailed Device Registration</h2>
      {_source_caption("Detailed Device Registration", report)}
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Status</th><th>Registered Node</th><th>IP Address</th>
            <th>Model</th><th>Protocol</th><th>Source</th>
          </tr>
        </thead>
        <tbody>
          {registration_rows}
        </tbody>
      </table>
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
            ("Profile", display_text(metadata.get("profile_name"))),
            ("Publisher", display_text(metadata.get("publisher"))),
            ("Artifacts enabled", "Yes" if metadata.get("artifacts_enabled") else "No"),
            ("Artifact redaction mode", display_text(metadata.get("artifact_redaction"))),
            ("TLS verification mode", "Enabled" if metadata.get("tls_verification") else "Disabled"),
            ("Phone inventory scope", "Enabled" if metadata.get("phone_inventory_enabled") else "Skipped"),
            ("Diagnostic capture", "Enabled" if metadata.get("diagnostic_capture") else "Disabled"),
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
          <tr><th>Name</th><td>{escape(cluster.name)}</td></tr>
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
                f"<td>{escape(node.name)}</td>"
                f"<td>{escape(node.address)}</td>"
                f"<td>{escape(node.role)}</td>"
                f"<td>{escape(display_bool(node.reachable))}</td>"
                "</tr>"
            )
            for node in report.facts.nodes
        )

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
            return '<tr><td colspan="7">No device inventory facts collected.</td></tr>'

        default_by_key = {
            _model_protocol_key(default.model, default.protocol): default.default_load
            for default in report.facts.device_load_defaults
        }
        rows = []
        for key, devices in _devices_by_model_protocol(report).items():
            model, protocol = key
            default_load = default_by_key.get(key)
            manual_load_count = sum(
                1
                for device in devices
                if _is_manual_load(device.configured_load, default_load)
            )
            missing_load_count = sum(1 for device in devices if not device.configured_load)
            unknown_default_count = len(devices) if key not in default_by_key else 0
            rows.append(
                "<tr>"
                f"<td>{escape(display_text(model))}</td>"
                f"<td>{escape(display_text(protocol))}</td>"
                f"<td>{escape(display_text(default_load))}</td>"
                f"<td>{len(devices)}</td>"
                f"<td>{manual_load_count}</td>"
                f"<td>{missing_load_count}</td>"
                f"<td>{unknown_default_count}</td>"
                "</tr>"
            )
        return "\n".join(rows)

    def _registration_rows(self, report: AssessmentReport) -> str:
        if not report.facts.registrations:
            return '<tr><td colspan="7">No device registration facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(registration.name))}</td>"
                f"<td>{escape(display_text(registration.status))}</td>"
                f"<td>{escape(display_text(registration.registered_node))}</td>"
                f"<td>{escape(display_text(registration.ip_address))}</td>"
                f"<td>{escape(display_text(registration.model))}</td>"
                f"<td>{escape(display_text(registration.protocol))}</td>"
                f"<td>{escape(display_text(registration.source))}</td>"
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

    def _service_rows(self, report: AssessmentReport) -> str:
        if not report.facts.services:
            return '<tr><td colspan="6">No service status facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(service.node)}</td>"
                f"<td>{escape(service.service_name)}</td>"
                f"<td>{escape(display_bool(service.activated))}</td>"
                f"<td>{escape(service.status)}</td>"
                f"<td>{escape(display_text(service.uptime_seconds))}</td>"
                f"<td>{escape(service.source)}</td>"
                "</tr>"
            )
            for service in report.facts.services
        )

    def _perf_counter_rows(self, report: AssessmentReport) -> str:
        if not report.facts.perf_counters:
            return '<tr><td colspan="7">No performance counter facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(counter.node)}</td>"
                f"<td>{escape(counter.object_name)}</td>"
                f"<td>{escape(counter.counter_name)}</td>"
                f"<td>{escape(display_text(counter.instance))}</td>"
                f"<td>{escape(display_text(counter.value))}</td>"
                f"<td>{counter.sample_count}</td>"
                f"<td>{escape(counter.source)}</td>"
                "</tr>"
            )
            for counter in report.facts.perf_counters
        )

    def _platform_check_rows(self, report: AssessmentReport) -> str:
        if not report.facts.platform_checks:
            return '<tr><td colspan="5">No platform check facts collected.</td></tr>'

        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(check.node)}</td>"
                f"<td>{escape(check.check_name)}</td>"
                f"<td>{escape(check.status)}</td>"
                f"<td>{escape(display_details(check.details))}</td>"
                f"<td>{escape(check.source)}</td>"
                "</tr>"
            )
            for check in report.facts.platform_checks
        )

    def _collector_issues_section(self, report: AssessmentReport) -> str:
        rows = []
        for result in report.collector_results:
            for warning in result.warnings:
                rows.append(
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
                    "<td>warning</td>"
                    f"<td>{escape(warning)}</td>"
                    "</tr>"
                )
            for error in result.errors:
                rows.append(
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
                    "<td>error</td>"
                    f"<td>{escape(error.exception_type)}: {escape(error.message)}</td>"
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
                    "<tr>"
                    f"<td>{escape(result.collector_name)}</td>"
                    f"<td>{escape(note)}</td>"
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
                rows.append(
                    "<tr>"
                    f"<td>{escape(display_text(result.collector_name))}</td>"
                    f"<td>{escape(display_text(evidence.source))}</td>"
                    f"<td>{escape(display_text(evidence.operation))}</td>"
                    f"<td>{escape(display_text(evidence.node))}</td>"
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
                ("Inventory-only devices", len(reconciliation.inventory_only)),
                ("Runtime-only devices", len(reconciliation.runtime_only)),
            )
        )
        inventory_only_rows = self._inventory_only_rows(reconciliation.inventory_only)
        runtime_only_rows = self._runtime_only_rows(reconciliation.runtime_only)

        return f"""
    <section>
      <h2>Inventory / Runtime Reconciliation</h2>
      <p class="meta">Informational name-based comparison between configured inventory facts
      and runtime registration facts. Differences are not health findings.</p>
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
      <h3>Inventory-only Devices</h3>
      <table>
        <thead><tr><th>Name</th><th>Model</th><th>Protocol</th><th>Device Pool</th><th>Location</th><th>Source</th></tr></thead>
        <tbody>
          {inventory_only_rows}
        </tbody>
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
                f"<td>{escape(display_text(registration.source))}</td>"
                "</tr>"
            )
            for registration in registrations
        )

    def _inventory_only_rows(self, devices: list[DeviceInventoryFact]) -> str:
        if not devices:
            return '<tr><td colspan="6">No inventory-only devices found.</td></tr>'
        return "\n".join(
            (
                "<tr>"
                f"<td>{escape(display_text(device.name))}</td>"
                f"<td>{escape(display_text(device.model))}</td>"
                f"<td>{escape(display_text(device.protocol))}</td>"
                f"<td>{escape(display_text(device.device_pool))}</td>"
                f"<td>{escape(display_text(device.location))}</td>"
                f"<td>{escape(display_text(device.source))}</td>"
                "</tr>"
            )
            for device in devices
        )

    def _finding_section(self, finding: HealthFinding) -> str:
        severity = escape(finding.severity.value)
        facts = "\n".join(f"<li>{escape(fact)}</li>" for fact in finding.facts)
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
            node = f" | Node: {escape(evidence.node)}" if evidence.node else ""
            artifact = ""
            if evidence.artifact_path:
                artifact = f" | Artifact: {escape(str(evidence.artifact_path))}"
            items.append(
                "<li>"
                f"Source: {escape(evidence.source)} | "
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


def _is_manual_load(configured_load: str | None, default_load: str | None) -> bool:
    if not configured_load or not default_load:
        return False
    return configured_load.strip().lower() != default_load.strip().lower()


def _is_sample_report(report: AssessmentReport) -> bool:
    return any(result.collector_name == "sample" for result in report.collector_results)


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
        "Device Load Summary": "Source: AXL listPhone summary inventory and device load default facts when collected.",
        "Detailed Device Inventory": detailed_inventory_caption,
    }
    planned_sections = {
        "Device Registration Summary": "Source: RISPort70 SelectCmDeviceExt. Real collector not implemented yet.",
        "Detailed Device Registration": "Source: RISPort70 SelectCmDeviceExt. Real collector not implemented yet.",
        "Services": "Source: Control Center Services. Real collector not implemented yet.",
        "Performance Counters": "Source: PerfMon. Real collector not implemented yet.",
        "Platform Checks": "Source: SSH/CLI fallback. Real collector not implemented yet.",
    }
    if section_name in axl_sections and _has_axl_evidence(report):
        return f'<p class="meta">{escape(axl_sections[section_name])}</p>'
    caption = planned_sections.get(section_name, "Source: Not recorded.")
    return f'<p class="meta">{escape(caption)}</p>'
