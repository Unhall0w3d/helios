"""Command-line interface for alpha assessment runs."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from cisco_collab_health.collectors.sample import SampleCollector
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.markdown import MarkdownReportBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ccha",
        description="Cisco Collaboration Health Assessment Tool alpha runner.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Report output format.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    engine = AssessmentEngine(
        collectors=[SampleCollector()],
        rules=[ClusterIdentityRule(), NodeReachabilityRule()],
    )
    report = engine.run()

    if args.format == "markdown":
        print(MarkdownReportBuilder().build(report))
    else:
        print(JsonReportBuilder().build(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
