"""Command-line interface for alpha assessment runs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from cisco_collab_health.application import run_assessment, tls_policy_from_args
from cisco_collab_health.config import (
    ensure_runtime_profile,
    select_or_create_runtime_profile,
)
from cisco_collab_health.menu import run_menu
from cisco_collab_health.status import StatusPrinter

_tls_policy_from_args = tls_policy_from_args


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
        "--artifact-dir",
        default="assessment_runs",
        help="Directory for local per-run artifacts. Defaults to assessment_runs/.",
    )
    parser.add_argument(
        "--no-artifacts",
        action="store_true",
        help="Do not write local parser/debug artifacts.",
    )
    parser.add_argument(
        "--artifact-redaction",
        choices=("none", "secrets"),
        default="secrets",
        help="Redaction mode for local API artifacts. Defaults to secrets.",
    )
    parser.add_argument(
        "--log-dir",
        default="logs",
        help="Directory for local troubleshooting logs. Defaults to logs/.",
    )
    parser.add_argument(
        "--no-logs",
        action="store_true",
        help="Do not write local troubleshooting logs.",
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
        help="Run a framework smoke test without prompting for connection details.",
    )
    parser.add_argument(
        "--probe-interfaces",
        action="store_true",
        help="Deprecated alias; Publisher preflight runs automatically after profile load.",
    )
    parser.add_argument(
        "--axl-port",
        type=int,
        default=8443,
        help="AXL HTTPS port.",
    )
    parser.add_argument(
        "--risport-port",
        type=int,
        default=8443,
        help="RISPort70 HTTPS port.",
    )
    parser.add_argument(
        "--control-center-port",
        type=int,
        default=8443,
        help="Control Center Services HTTPS port.",
    )
    parser.add_argument(
        "--perfmon-port",
        type=int,
        default=8443,
        help="PerfMon HTTPS port.",
    )
    parser.add_argument(
        "--collect-phone-inventory",
        action="store_true",
        help="Opt in to AXL listPhone summary inventory collection for small lab clusters.",
    )
    tls_group = parser.add_mutually_exclusive_group()
    tls_group.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify CUCM HTTPS certificates using system trust or --ca-bundle.",
    )
    tls_group.add_argument(
        "--insecure",
        action="store_true",
        help="Disable CUCM HTTPS certificate verification. This is the alpha default.",
    )
    parser.add_argument(
        "--ca-bundle",
        default=None,
        help="CA bundle path used when --verify-tls is enabled.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    provided_args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(provided_args)
    _validate_args(parser, args)
    status_stream = sys.stderr if args.format == "json" else sys.stdout
    status = StatusPrinter(stream=status_stream)

    try:
        if not provided_args:
            return run_menu(args, status, run_assessment)
        return _run(args, status)
    except KeyboardInterrupt:
        status.warn("Interrupted by user")
        return 130
    except (OSError, ValueError) as exc:
        status.fail(str(exc))
        return 1


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.ca_bundle and not args.verify_tls:
        parser.error("--ca-bundle requires --verify-tls")


def _run(args: argparse.Namespace, status: StatusPrinter) -> int:
    if args.skip_profile:
        return run_assessment(args, status, None)

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

    return run_assessment(args, status, runtime_profile)


if __name__ == "__main__":
    raise SystemExit(main())
