"""Command-line interface for alpha assessment runs."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from cisco_collab_health.artifacts import (
    ArtifactStore,
    RunLogStore,
    write_assessment_artifacts,
    write_log_bundle,
    write_preflight_artifacts,
)
from cisco_collab_health.collector_registry import select_collectors
from cisco_collab_health.collectors.base import CollectionContext, TlsPolicy
from cisco_collab_health.config import (
    RuntimeProfile,
    ensure_runtime_profile,
    select_or_create_runtime_profile,
)
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.interfaces import PreflightResult, run_publisher_preflight
from cisco_collab_health.menu import run_menu
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
from cisco_collab_health.rules.basic import ClusterIdentityRule, NodeReachabilityRule
from cisco_collab_health.status import StatusPrinter


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
        choices=("none", "secrets", "customer-data"),
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
        "--verify-tls",
        action="store_true",
        help="Verify CUCM HTTPS certificates using system trust or --ca-bundle.",
    )
    parser.add_argument(
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
    args = build_parser().parse_args(provided_args)
    status_stream = sys.stderr if args.format == "json" else sys.stdout
    status = StatusPrinter(stream=status_stream)

    try:
        if not provided_args:
            return run_menu(args, status, _run_assessment)
        return _run(args, status)
    except KeyboardInterrupt:
        status.warn("Interrupted by user")
        return 130
    except (OSError, ValueError) as exc:
        status.fail(str(exc))
        return 1


def _run(args: argparse.Namespace, status: StatusPrinter) -> int:
    if args.skip_profile:
        return _run_assessment(args, status, None)

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

    return _run_assessment(args, status, runtime_profile)


def _run_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    runtime_profile: RuntimeProfile | None,
) -> int:
    tls_policy = _tls_policy_from_args(args)
    context = CollectionContext(tls=tls_policy)
    run_started = datetime.now()
    artifact_store: ArtifactStore | None = None
    log_store: RunLogStore | None = None
    profile_name = "sample"

    if runtime_profile is not None:
        profile_name = runtime_profile.stored.name
        log_store = _create_log_store(args, status, profile_name, run_started)
        _write_log_manifest(log_store, profile_name=profile_name, publisher_ip=runtime_profile.stored.publisher_ip)
        status.stage("Loading connection profile")
        for warning in runtime_profile.warnings:
            status.warn(warning)
        context = CollectionContext(
            target=runtime_profile.stored.publisher_ip,
            username=runtime_profile.stored.gui_username,
            publisher_ip=runtime_profile.stored.publisher_ip,
            gui_username=runtime_profile.stored.gui_username,
            gui_password=runtime_profile.gui_password,
            os_username=runtime_profile.stored.os_username,
            os_password=runtime_profile.os_password,
            axl_port=args.axl_port,
            risport_port=args.risport_port,
            control_center_port=args.control_center_port,
            perfmon_port=args.perfmon_port,
            tls=tls_policy,
        )
        artifact_store = _create_artifact_store(args, status, profile_name, run_started)
        context = replace(context, artifact_store=artifact_store)
        _write_manifest(
            artifact_store,
            profile_name=profile_name,
            publisher_ip=runtime_profile.stored.publisher_ip,
            skipped_profile=False,
            artifact_redaction=args.artifact_redaction,
            tls_verify=tls_policy.verify,
            tls_ca_bundle=str(tls_policy.ca_bundle) if tls_policy.ca_bundle else None,
        )
        status.ok(f"Profile loaded: {runtime_profile.stored.name}")
        _print_tls_status(tls_policy, status)
        status.stage(f"Running Publisher preflight: {runtime_profile.stored.publisher_ip}")
        preflight = run_publisher_preflight(
            context,
            axl_port=args.axl_port,
            risport_port=args.risport_port,
            control_center_port=args.control_center_port,
            perfmon_port=args.perfmon_port,
        )
        _print_preflight_status(preflight, status)
        if artifact_store:
            write_preflight_artifacts(artifact_store, runtime_profile.stored.publisher_ip, preflight)
            status.ok(f"Preflight artifacts written: {artifact_store.root}")
    else:
        log_store = _create_log_store(args, status, profile_name, run_started)
        _write_log_manifest(log_store, profile_name=profile_name, publisher_ip=None)
        status.warn("Skipping profile and Publisher preflight")
        artifact_store = _create_artifact_store(args, status, profile_name, run_started)
        context = replace(context, artifact_store=artifact_store)
        _write_manifest(
            artifact_store,
            profile_name=profile_name,
            publisher_ip=None,
            skipped_profile=True,
            artifact_redaction=args.artifact_redaction,
            tls_verify=tls_policy.verify,
            tls_ca_bundle=str(tls_policy.ca_bundle) if tls_policy.ca_bundle else None,
        )

    collectors = select_collectors(
        preflight if runtime_profile is not None else None,
        smoke_test=runtime_profile is None,
    )
    if collectors:
        status.info("Collectors enabled: " + ", ".join(collector.name for collector in collectors))
    else:
        status.warn("No API collectors enabled")

    status.stage("Running collectors")
    engine = AssessmentEngine(
        collectors=collectors,
        rules=[ClusterIdentityRule(), NodeReachabilityRule()],
    )
    report = engine.run(context)
    status.ok("Collectors completed")
    for collector_result in report.collector_results:
        for warning in collector_result.warnings:
            status.warn(f"{collector_result.collector_name}: {warning}")
        for error in collector_result.errors:
            status.fail(
                f"{collector_result.collector_name}: "
                f"{error.exception_type}: {error.message}"
            )
    if artifact_store:
        write_assessment_artifacts(artifact_store, report)
        status.ok(f"Assessment artifacts written: {artifact_store.root}")

    html_report_path = None
    if not args.no_html_report:
        status.stage("Writing HTML report")
        try:
            html_report_path = _write_html_report(report, args.html_report)
            status.ok(f"HTML report written: {html_report_path}")
        except OSError as exc:
            status.fail(f"Unable to write HTML report: {exc}")

    status.stage("Rendering terminal output")
    if args.format == "json":
        print(JsonReportBuilder().build(report))
        summary_text = ExecutiveSummaryBuilder().build(report, str(html_report_path) if html_report_path else None)
    else:
        summary_text = ExecutiveSummaryBuilder().build(report, str(html_report_path) if html_report_path else None)
        print(summary_text)

    if log_store:
        write_log_bundle(
            log_store,
            report=report,
            summary_text=summary_text,
            artifact_store=artifact_store,
            html_report_path=html_report_path,
        )
        status.ok(f"Troubleshooting logs written: {log_store.root}")

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


def _create_artifact_store(
    args: argparse.Namespace,
    status: StatusPrinter,
    profile_name: str,
    run_started: datetime,
) -> ArtifactStore | None:
    if args.no_artifacts:
        status.warn("Skipping local artifact storage")
        return None

    status.stage("Preparing local artifact storage")
    store = ArtifactStore.create(
        args.artifact_dir,
        profile_name,
        run_started,
        redaction_mode=args.artifact_redaction,
    )
    status.ok(f"Artifact directory: {store.root}")
    return store


def _create_log_store(
    args: argparse.Namespace,
    status: StatusPrinter,
    profile_name: str,
    run_started: datetime,
) -> RunLogStore | None:
    if args.no_logs:
        status.warn("Skipping troubleshooting log storage")
        return None

    store = RunLogStore.create(args.log_dir, profile_name, run_started)
    status.attach_log_stream(store.open_run_log())
    status.ok(f"Troubleshooting log directory: {store.root}")
    return store


def _write_manifest(
    store: ArtifactStore | None,
    *,
    profile_name: str,
    publisher_ip: str | None,
    skipped_profile: bool,
    artifact_redaction: str,
    tls_verify: bool,
    tls_ca_bundle: str | None,
) -> None:
    if not store:
        return

    store.write_manifest(
        {
            "tool": "helios",
            "profile_name": profile_name,
            "publisher_ip": publisher_ip,
            "skipped_profile": skipped_profile,
            "artifact_redaction": artifact_redaction,
            "tls_verify": tls_verify,
            "tls_ca_bundle": tls_ca_bundle,
        }
    )


def _tls_policy_from_args(args: argparse.Namespace) -> TlsPolicy:
    verify = bool(args.verify_tls and not args.insecure)
    ca_bundle = Path(args.ca_bundle).expanduser() if args.ca_bundle else None
    return TlsPolicy(verify=verify, ca_bundle=ca_bundle)


def _print_tls_status(policy: TlsPolicy, status: StatusPrinter) -> None:
    if policy.verify:
        detail = f" using CA bundle {policy.ca_bundle}" if policy.ca_bundle else ""
        status.info(f"TLS verification: enabled{detail}")
    else:
        status.warn("TLS verification: disabled")


def _write_log_manifest(
    store: RunLogStore | None,
    *,
    profile_name: str,
    publisher_ip: str | None,
) -> None:
    if not store:
        return

    store.write_manifest(
        {
            "tool": "helios",
            "profile_name": profile_name,
            "publisher_ip": publisher_ip,
        }
    )


def _print_preflight_status(preflight: PreflightResult, status: StatusPrinter) -> None:
    for check in preflight.connectivity:
        message = f"{check.name}: {check.target}"
        if check.available:
            status.ok(message)
        else:
            detail = f" - {check.reason}" if check.reason else ""
            status.warn(f"{message}{detail}")

    for interface in preflight.interfaces:
        message = f"{interface.name}: {interface.endpoint}"
        if interface.available:
            status.ok(message)
        else:
            detail = f" - {interface.reason}" if interface.reason else ""
            status.warn(f"{message}{detail}")

    if preflight.available_interfaces:
        status.info("Enabled interfaces: " + ", ".join(preflight.available_interfaces))
    else:
        status.warn("No Publisher API interfaces passed preflight")


if __name__ == "__main__":
    raise SystemExit(main())
