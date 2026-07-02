"""Command-line interface for alpha assessment runs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.config import ensure_runtime_profile, select_or_create_runtime_profile
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccha",
        description="Cisco Collaboration Health Assessment Tool alpha runner.",
    )
    parser.add_argument(
        "--format",
        choices=("summary", "json"),
        default="summary",
        help="Terminal output format.",
    )
    parser.add_argument(
        "--html-report",
        default=None,
        help="Path for the styled HTML report. Defaults to reports/assessment-<timestamp>.html.",
    )
    parser.add_argument(
        "--no-html-report",
        action="store_true",
        help="Do not write the styled HTML report.",
    )
    parser.add_argument(
        "--profile",
        help="Local connection profile name. If omitted, choose from saved profiles or create one.",
    )
    parser.add_argument(
        "--reset-profile",
        action="store_true",
        help="Replace the saved local profile and stored credentials.",
    )
    parser.add_argument(
        "--no-save-credentials",
        action="store_true",
        help="Prompt for passwords but do not store them in the OS credential store.",
    )
    parser.add_argument(
        "--skip-profile",
        action="store_true",
        help="Run the current offline sample assessment without prompting for connection details.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    context = CollectionContext()
    if not args.skip_profile:
        if args.profile:
            runtime_profile = ensure_runtime_profile(
                args.profile,
                reset=args.reset_profile,
                save_credentials=not args.no_save_credentials,
            )
        else:
            runtime_profile = select_or_create_runtime_profile(
                reset=args.reset_profile,
                save_credentials=not args.no_save_credentials,
            )
        for warning in runtime_profile.warnings:
            print(f"warning: {warning}", file=sys.stderr)
        context = CollectionContext(
            target=runtime_profile.stored.publisher_ip,
            username=runtime_profile.stored.gui_username,
            publisher_ip=runtime_profile.stored.publisher_ip,
            gui_username=runtime_profile.stored.gui_username,
            gui_password=runtime_profile.gui_password,
            os_username=runtime_profile.stored.os_username,
            os_password=runtime_profile.os_password,
        )

    engine = AssessmentEngine(
        collectors=[SampleCollector()],
        rules=[ClusterIdentityRule(), NodeReachabilityRule()],
    )
    report = engine.run(context)

    html_report_path = None
    if not args.no_html_report:
        html_report_path = _write_html_report(report, args.html_report)

    if args.format == "json":
        print(JsonReportBuilder().build(report))
    else:
        print(ExecutiveSummaryBuilder().build(report, str(html_report_path) if html_report_path else None))

    return 0


def _write_html_report(report: AssessmentReport, requested_path: str | None) -> Path:
    if requested_path:
        path = Path(requested_path).expanduser()
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path("reports") / f"assessment-{timestamp}.html"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HtmlReportBuilder().build(report), encoding="utf-8")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
