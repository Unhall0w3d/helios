"""Terminal Executive Summary builder."""

from __future__ import annotations

from collections import Counter

from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.findings import FindingSeverity


class ExecutiveSummaryBuilder:
    """Builds a concise terminal summary for an assessment result."""

    def build(self, report: AssessmentReport, html_report_path: str | None = None) -> str:
        severity_counts = Counter(finding.severity for finding in report.findings)
        critical_count = severity_counts[FindingSeverity.CRITICAL]
        warning_count = severity_counts[FindingSeverity.WARNING]
        info_count = severity_counts[FindingSeverity.INFO]
        collector_error_count = sum(len(result.errors) for result in report.collector_results)

        lines = [
            "Executive Summary",
            "=================",
            "",
        ]

        if report.facts.cluster is not None:
            cluster = report.facts.cluster
            lines.extend(
                [
                    f"Cluster: {cluster.name}",
                    f"Product: {cluster.product}",
                    f"Version: {cluster.version}",
                ]
            )
        else:
            lines.append("Cluster: unknown")

        lines.extend(
            [
                f"Nodes discovered: {len(report.facts.nodes)}",
                f"Findings: {critical_count} critical, {warning_count} warning, {info_count} info",
                f"Collector errors: {collector_error_count}",
                "",
                "Highlights:",
            ]
        )

        highlighted_findings = [
            finding
            for finding in report.findings
            if finding.severity in {FindingSeverity.CRITICAL, FindingSeverity.WARNING}
        ]
        if not highlighted_findings:
            highlighted_findings = report.findings[:3]

        if highlighted_findings:
            for finding in highlighted_findings:
                lines.append(f"- [{finding.severity.value}] {finding.title}")
        else:
            lines.append("- No findings generated.")

        if html_report_path:
            lines.extend(["", f"HTML report: {html_report_path}"])

        return "\n".join(lines).rstrip() + "\n"
