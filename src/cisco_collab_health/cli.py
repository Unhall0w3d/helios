"""Command-line interface for alpha assessment runs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from cisco_collab_health.application import (
    run_assessment,
    run_multi_assessment,
    tls_policy_from_args,
)
from cisco_collab_health.config import (
    ASSESSABLE_TECHNOLOGIES,
    SUPPORTED_TECHNOLOGIES,
    ensure_runtime_profile,
    AssessmentProfile,
    AssessmentTarget,
    load_assessment_profiles,
    resolve_assessment_targets,
    save_assessment_profiles,
    select_or_create_runtime_profile,
)
from cisco_collab_health.menu import run_menu
from cisco_collab_health.status import StatusPrinter

_tls_policy_from_args = tls_policy_from_args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aletheiauc",
        description="AletheiaUC alpha runner for Cisco Collaboration health assessments.",
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
        "--customer-safe-report",
        action="store_true",
        help=(
            "Mask customer identifiers and omit sensitive detail from the HTML report. "
            "Raw artifacts and JSON remain private diagnostic output."
        ),
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
        "--export-review-zip",
        action="store_true",
        help=(
            "Write the self-contained troubleshooting bundle as a ZIP file in the "
            "current user's Downloads folder."
        ),
    )
    parser.add_argument(
        "--profile",
        help="Local connection profile name. If omitted, choose from saved profiles or create one.",
    )
    parser.add_argument(
        "--assessment-profile",
        help="Multi-technology assessment profile containing independently credentialed targets.",
    )
    parser.add_argument(
        "--assessment-target",
        action="append",
        default=[],
        metavar="ID:TECHNOLOGY:PROFILE",
        help="Add/update a target in --assessment-profile; repeat for multiple technologies.",
    )
    parser.add_argument(
        "--product",
        choices=tuple(sorted(SUPPORTED_TECHNOLOGIES)),
        default="cucm",
        help="Target technology. CUCM and CUC collectors are currently available.",
    )
    parser.add_argument(
        "--reset-profile",
        action="store_true",
        help="Replace the saved local profile and stored credentials.",
    )
    parser.add_argument(
        "--reset-technology",
        choices=tuple(sorted(SUPPORTED_TECHNOLOGIES)),
        help="Clear only one technology section in the selected profile and re-prompt for it.",
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
    parser.add_argument(
        "--phone-inventory-page-size",
        type=int,
        default=500,
        help="AXL listPhone page size when --collect-phone-inventory is enabled.",
    )
    parser.add_argument(
        "--phone-inventory-max-devices",
        type=int,
        default=2000,
        help="Maximum phones to request through AXL listPhone in one run.",
    )
    parser.add_argument(
        "--diagnostic-capture",
        action="store_true",
        help=(
            "Capture bounded read-only API discovery data for future collector development. "
            "May produce large, customer-sensitive artifacts."
        ),
    )
    parser.add_argument(
        "--diagnostic-max-devices",
        type=int,
        default=2000,
        help="Maximum devices requested by the diagnostic RISPort snapshot (maximum 2000).",
    )
    parser.add_argument(
        "--diagnostic-axl-page-size",
        type=int,
        default=250,
        help="Page size for each diagnostic AXL inventory operation.",
    )
    parser.add_argument(
        "--diagnostic-axl-max-records",
        type=int,
        default=500,
        help="Maximum records retained per diagnostic AXL inventory operation.",
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
            return run_menu(args, status, run_assessment, run_multi_assessment)
        return _run(args, status)
    except KeyboardInterrupt:
        status.warn("Interrupted by user")
        return 130
    except (OSError, ValueError) as exc:
        status.fail(str(exc))
        return 1


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.assessment_profile and args.profile:
        parser.error("--assessment-profile cannot be combined with --profile")
    if args.assessment_profile and args.product != "cucm":
        parser.error("--product is defined by each target in --assessment-profile")
    if (
        not args.assessment_profile
        and not args.skip_profile
        and args.product not in ASSESSABLE_TECHNOLOGIES
    ):
        parser.error(f"Assessment collectors are not available for --product {args.product}")
    if args.reset_technology and not args.profile:
        parser.error("--reset-technology requires --profile")
    if args.assessment_target and not args.assessment_profile:
        parser.error("--assessment-target requires --assessment-profile")
    if args.ca_bundle and not args.verify_tls:
        parser.error("--ca-bundle requires --verify-tls")
    if args.export_review_zip and args.no_logs:
        parser.error("--export-review-zip cannot be combined with --no-logs")
    if args.phone_inventory_page_size < 1:
        parser.error("--phone-inventory-page-size must be at least 1")
    if args.phone_inventory_max_devices < 1:
        parser.error("--phone-inventory-max-devices must be at least 1")
    if not 1 <= args.diagnostic_max_devices <= 2000:
        parser.error("--diagnostic-max-devices must be between 1 and 2000")
    if args.diagnostic_axl_page_size < 1:
        parser.error("--diagnostic-axl-page-size must be at least 1")
    if args.diagnostic_axl_max_records < 1:
        parser.error("--diagnostic-axl-max-records must be at least 1")


def _run(args: argparse.Namespace, status: StatusPrinter) -> int:
    if args.skip_profile:
        return run_assessment(args, status, None)

    if args.assessment_profile:
        assessments = load_assessment_profiles()
        assessment: AssessmentProfile | None
        if args.assessment_target:
            parsed_targets = []
            for specification in args.assessment_target:
                parts = specification.split(":", 2)
                if len(parts) != 3:
                    raise ValueError("Assessment targets must use ID:TECHNOLOGY:PROFILE format.")
                parsed_targets.append(AssessmentTarget(*parts))
            assessment = AssessmentProfile(args.assessment_profile, tuple(parsed_targets))
            assessments[assessment.name] = assessment
            save_assessment_profiles(assessments)
        else:
            assessment = assessments.get(args.assessment_profile)
        if assessment is None:
            available = ", ".join(sorted(assessments)) or "none"
            raise ValueError(
                f"Assessment profile '{args.assessment_profile}' was not found. Available: {available}."
            )
        targets = resolve_assessment_targets(
            assessment,
            reset=args.reset_profile,
            save_credentials=not args.no_save_credentials,
        )
        return run_multi_assessment(args, status, assessment.name, targets)

    if args.profile:
        runtime_profile = ensure_runtime_profile(
            args.profile,
            technology=args.product,
            reset_technology=args.reset_technology == args.product,
            reset=args.reset_profile,
            save_credentials=not args.no_save_credentials,
        )
    else:
        runtime_profile = select_or_create_runtime_profile(
            technology=args.product,
            reset=args.reset_profile,
            save_credentials=not args.no_save_credentials,
        )

    return run_assessment(args, status, runtime_profile)


if __name__ == "__main__":
    raise SystemExit(main())
