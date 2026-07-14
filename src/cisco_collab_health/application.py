"""Assessment application orchestration."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from cisco_collab_health.artifacts import (
    ArtifactStore,
    RunLogStore,
    export_review_zip,
    write_assessment_artifacts,
    write_log_bundle,
    write_preflight_artifacts,
)
from cisco_collab_health.collector_registry import select_collectors
from cisco_collab_health.collectors.base import Collector, TargetPipelineCollector
from cisco_collab_health.config import (
    AssessmentTarget,
    RuntimeProfile,
)
from cisco_collab_health.engine import AssessmentEngine
from cisco_collab_health.interfaces import PreflightResult, run_publisher_preflight
from cisco_collab_health.models.assessment import AssessmentReport
from cisco_collab_health.models.runtime import CollectionContext, HostKeyApproval
from cisco_collab_health.reports.html import HtmlReportBuilder
from cisco_collab_health.reports.json import JsonReportBuilder
from cisco_collab_health.reports.summary import ExecutiveSummaryBuilder
from cisco_collab_health.rules.basic import (
    ClusterIdentityRule,
    CollectorHealthRule,
    NodeReachabilityRule,
    PlatformCheckSummaryRule,
)
from cisco_collab_health.rules.base import HealthRule
from cisco_collab_health.status import StatusPrinter
from cisco_collab_health.technologies import load_plugins
from cisco_collab_health.transport.tls import TlsPolicy


def _host_key_approval(args: argparse.Namespace) -> HostKeyApproval | None:
    """Return an explicit SSH host-key approval prompt when enrollment is enabled."""

    if not (
        getattr(args, "_prompt_ssh_host_keys", False) or args.accept_new_host_key
    ):
        return None

    def approve(hostname: str, algorithm: str, fingerprint: str) -> bool:
        print("\nSSH host key verification required")
        print(f"Host: {hostname}")
        print(f"Algorithm: {algorithm}")
        print(f"SHA-256 fingerprint: {fingerprint}")
        answer = input(
            "After verifying this fingerprint out of band, trust and save this key? [y/N]: "
        ).strip().lower()
        return answer in {"y", "yes"}

    return approve


def run_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    runtime_profile: RuntimeProfile | None,
) -> int:
    """Run one assessment from parsed CLI arguments and an optional profile."""

    tls_policy = tls_policy_from_args(args)
    host_key_approval = _host_key_approval(args)
    host_key_enrollment = host_key_approval is not None
    ssh_parallel_workers = getattr(args, "ssh_parallel_workers", 3)
    context = CollectionContext(
        product=args.product,
        tls=tls_policy,
        accept_new_host_key=host_key_enrollment,
        host_key_approval=host_key_approval,
        progress=status.info,
        ssh_parallel_workers=ssh_parallel_workers,
        collect_phone_inventory=args.collect_phone_inventory,
        phone_inventory_page_size=args.phone_inventory_page_size,
        phone_inventory_max_devices=args.phone_inventory_max_devices,
        diagnostic_capture=args.diagnostic_capture,
        diagnostic_max_devices=args.diagnostic_max_devices,
        diagnostic_axl_page_size=args.diagnostic_axl_page_size,
        diagnostic_axl_max_records=args.diagnostic_axl_max_records,
        diagnostic_cupi_max_records=args.diagnostic_cupi_max_records,
    )
    run_started = datetime.now()
    artifact_store: ArtifactStore | None = None
    log_store: RunLogStore | None = None
    profile_name = "sample"

    if runtime_profile is not None:
        profile_name = runtime_profile.stored.name
        log_store = _create_log_store(args, status, profile_name, run_started)
        _write_log_manifest(
            log_store,
            profile_name=profile_name,
            publisher_ip=runtime_profile.stored.publisher_ip,
        )
        status.stage("Loading connection profile")
        for warning in runtime_profile.warnings:
            status.warn(warning)
        context = CollectionContext(
            target=runtime_profile.stored.publisher_ip,
            username=runtime_profile.stored.gui_username,
            product=args.product,
            publisher_ip=runtime_profile.stored.publisher_ip,
            gui_username=runtime_profile.stored.gui_username,
            gui_password=runtime_profile.gui_password,
            os_username=runtime_profile.stored.os_username,
            os_password=runtime_profile.os_password,
            axl_port=args.axl_port,
            risport_port=args.risport_port,
            control_center_port=args.control_center_port,
            perfmon_port=args.perfmon_port,
            collect_phone_inventory=args.collect_phone_inventory,
            phone_inventory_page_size=args.phone_inventory_page_size,
            phone_inventory_max_devices=args.phone_inventory_max_devices,
            diagnostic_capture=args.diagnostic_capture,
            diagnostic_max_devices=args.diagnostic_max_devices,
            diagnostic_axl_page_size=args.diagnostic_axl_page_size,
            diagnostic_axl_max_records=args.diagnostic_axl_max_records,
            diagnostic_cupi_max_records=args.diagnostic_cupi_max_records,
            tls=tls_policy,
            accept_new_host_key=host_key_enrollment,
            host_key_approval=host_key_approval,
            progress=status.info,
            ssh_parallel_workers=ssh_parallel_workers,
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
        if args.product == "cucm":
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
                write_preflight_artifacts(
                    artifact_store,
                    runtime_profile.stored.publisher_ip,
                    preflight,
                )
                status.ok(f"Preflight artifacts written: {artifact_store.root}")
        else:
            status.info("Unity Connection target: CUCM AXL/serviceability preflight skipped")
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
        diagnostic_capture=args.diagnostic_capture and runtime_profile is not None,
        product=args.product,
    )
    if collectors:
        status.info("Collectors enabled: " + ", ".join(collector.name for collector in collectors))
    else:
        status.warn("No API collectors enabled")

    status.stage("Running collectors")
    engine = AssessmentEngine(
        collectors=collectors,
        rules=_assessment_rules((args.product,)),
    )
    report = engine.run(context)
    report = replace(
        report,
        runtime_metadata={
            "profile_name": profile_name,
            "publisher": context.publisher_ip,
            "artifacts_enabled": artifact_store is not None,
            "artifact_redaction": args.artifact_redaction if artifact_store else None,
            "tls_verification": tls_policy.verify,
            "ssh_accept_new_host_key": context.accept_new_host_key,
            "phone_inventory_enabled": context.collect_phone_inventory
            or context.diagnostic_capture,
            "diagnostic_capture": context.diagnostic_capture,
            "customer_safe_report": args.customer_safe_report,
        },
    )
    status.ok("Collectors completed")
    if context.diagnostic_capture:
        _print_interface_validation_status(report, status)
    for collector_result in report.collector_results:
        for warning in collector_result.warnings:
            status.warn(f"{collector_result.collector_name}: {warning}")
        for error in collector_result.errors:
            status.fail(
                f"{collector_result.collector_name}: {error.exception_type}: {error.message}"
            )
    if artifact_store:
        write_assessment_artifacts(artifact_store, report)
        status.ok(f"Assessment artifacts written: {artifact_store.root}")

    html_report_path = None
    customer_safe_html_report_path = None
    if not args.no_html_report:
        status.stage("Writing HTML report")
        try:
            html_report_path = _write_html_report(
                report,
                args.html_report,
                customer_safe=args.customer_safe_report,
                template=args.html_template,
            )
            status.ok(f"HTML report written: {html_report_path}")
            if log_store:
                customer_safe_html_report_path = _write_html_report(
                    report,
                    str(_customer_safe_report_path(html_report_path)),
                    customer_safe=True,
                    template=args.html_template,
                )
                status.ok("Customer-safe HTML staged for the review ZIP")
        except OSError as exc:
            status.fail(f"Unable to write HTML report: {exc}")

    status.stage("Rendering terminal output")
    if args.format == "json":
        print(JsonReportBuilder().build(report))
        summary_text = ExecutiveSummaryBuilder().build(
            report,
            str(html_report_path) if html_report_path else None,
        )
    else:
        summary_text = ExecutiveSummaryBuilder().build(
            report,
            str(html_report_path) if html_report_path else None,
        )
        print(summary_text)

    if log_store:
        try:
            write_log_bundle(
                log_store,
                report=report,
                summary_text=summary_text,
                artifact_store=artifact_store,
                html_report_path=html_report_path,
                customer_safe_html_report_path=customer_safe_html_report_path,
            )
        except Exception as exc:
            status.fail(f"Unable to finalize troubleshooting logs: {exc}")
            return 1
        status.ok(f"Troubleshooting logs written: {log_store.root}")
        if args.export_review_zip:
            status.stage("Exporting review ZIP")
            status.warn("Review ZIP contains private diagnostic material; review before sharing.")
            try:
                review_zip = export_review_zip(log_store)
            except Exception as exc:
                status.fail(f"Unable to export review ZIP: {exc}")
                return 1
            status.ok(f"Review ZIP written: {review_zip}")

    return 0


def run_multi_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    assessment_name: str,
    targets: list[tuple[AssessmentTarget, RuntimeProfile]],
) -> int:
    """Run independently credentialed technology targets into one report."""

    tls_policy = tls_policy_from_args(args)
    host_key_approval = _host_key_approval(args)
    host_key_enrollment = host_key_approval is not None
    ssh_parallel_workers = getattr(args, "ssh_parallel_workers", 3)
    run_started = datetime.now()
    log_store = _create_log_store(args, status, assessment_name, run_started)
    _write_log_manifest(log_store, profile_name=assessment_name, publisher_ip=None)
    artifact_store = _create_artifact_store(args, status, assessment_name, run_started)
    address_targets: dict[str, list[str]] = {}
    for target, runtime in targets:
        address_targets.setdefault(runtime.stored.publisher_ip.strip().lower(), []).append(
            target.target_id
        )
    duplicate_addresses = [
        f"{address}: {', '.join(ids)}" for address, ids in address_targets.items() if len(ids) > 1
    ]
    if duplicate_addresses:
        status.fail(
            "Target addresses must be unique across technologies. Correct these before retrying: "
            + "; ".join(duplicate_addresses)
        )
        return 1
    pipelines: list[Collector] = []
    target_metadata = []
    for target, runtime in targets:
        status.stage(f"Preparing {target.target_id} ({target.technology})")
        context = CollectionContext(
            target=runtime.stored.publisher_ip,
            publisher_ip=runtime.stored.publisher_ip,
            username=runtime.stored.gui_username,
            product=target.technology,
            target_id=target.target_id,
            gui_username=runtime.stored.gui_username,
            gui_password=runtime.gui_password,
            os_username=runtime.stored.os_username,
            os_password=runtime.os_password,
            axl_port=args.axl_port,
            risport_port=args.risport_port,
            control_center_port=args.control_center_port,
            perfmon_port=args.perfmon_port,
            collect_phone_inventory=args.collect_phone_inventory,
            phone_inventory_page_size=args.phone_inventory_page_size,
            phone_inventory_max_devices=args.phone_inventory_max_devices,
            diagnostic_capture=args.diagnostic_capture,
            diagnostic_max_devices=args.diagnostic_max_devices,
            diagnostic_axl_page_size=args.diagnostic_axl_page_size,
            diagnostic_axl_max_records=args.diagnostic_axl_max_records,
            diagnostic_cupi_max_records=args.diagnostic_cupi_max_records,
            tls=tls_policy,
            artifact_store=artifact_store,
            accept_new_host_key=host_key_enrollment,
            host_key_approval=host_key_approval,
            progress=status.info,
            ssh_parallel_workers=ssh_parallel_workers,
        )
        preflight = None
        if target.technology == "cucm":
            preflight = run_publisher_preflight(
                context,
                axl_port=args.axl_port,
                risport_port=args.risport_port,
                control_center_port=args.control_center_port,
                perfmon_port=args.perfmon_port,
            )
            _print_preflight_status(preflight, status)
            if artifact_store:
                write_preflight_artifacts(
                    artifact_store,
                    f"{target.target_id}--{runtime.stored.publisher_ip}",
                    preflight,
                )
        collectors = select_collectors(
            preflight,
            diagnostic_capture=args.diagnostic_capture,
            product=target.technology,
        )
        pipelines.append(
            TargetPipelineCollector(
                target_id=target.target_id,
                technology=target.technology,
                collectors=tuple(collectors),
                target_context=context,
            )
        )
        target_metadata.append(
            {
                "target_id": target.target_id,
                "technology": target.technology,
                "connection_profile": target.connection_profile,
                "address": runtime.stored.publisher_ip,
            }
        )
    if artifact_store:
        artifact_store.write_manifest(
            {
                "tool": "aletheiauc",
                "assessment_profile": assessment_name,
                "targets": target_metadata,
                "artifact_redaction": args.artifact_redaction,
                "tls_verify": tls_policy.verify,
                "tls_ca_bundle": str(tls_policy.ca_bundle) if tls_policy.ca_bundle else None,
            }
        )
    status.stage("Running multi-technology collectors")
    engine = AssessmentEngine(
        collectors=pipelines,
        rules=_assessment_rules(target.technology for target, _ in targets),
    )
    report = engine.run(CollectionContext(product="multi", artifact_store=artifact_store))
    report = replace(
        report,
        runtime_metadata={
            "assessment_profile": assessment_name,
            "targets": target_metadata,
            "artifacts_enabled": artifact_store is not None,
            "artifact_redaction": args.artifact_redaction if artifact_store else None,
            "tls_verification": tls_policy.verify,
            "ssh_accept_new_host_key": host_key_enrollment,
            "diagnostic_capture": args.diagnostic_capture,
            "customer_safe_report": args.customer_safe_report,
        },
    )
    status.ok("Multi-technology collectors completed")
    for result in report.collector_results:
        for warning in result.warnings:
            status.warn(f"{result.collector_name}: {warning}")
        for error in result.errors:
            status.fail(f"{result.collector_name}: {error.exception_type}: {error.message}")
    if artifact_store:
        write_assessment_artifacts(artifact_store, report)
    html_report_path = None
    customer_safe_html_report_path = None
    if not args.no_html_report:
        html_report_path = _write_html_report(
            report,
            args.html_report,
            customer_safe=args.customer_safe_report,
            template=args.html_template,
        )
        status.ok(f"HTML report written: {html_report_path}")
        if log_store:
            customer_safe_html_report_path = _write_html_report(
                report,
                str(_customer_safe_report_path(html_report_path)),
                customer_safe=True,
                template=args.html_template,
            )
            status.ok("Customer-safe HTML staged for the review ZIP")
    summary_text = ExecutiveSummaryBuilder().build(
        report,
        str(html_report_path) if html_report_path else None,
    )
    if args.format == "json":
        print(JsonReportBuilder().build(report))
    else:
        print(summary_text)
    if log_store:
        try:
            write_log_bundle(
                log_store,
                report=report,
                summary_text=summary_text,
                artifact_store=artifact_store,
                html_report_path=html_report_path,
                customer_safe_html_report_path=customer_safe_html_report_path,
            )
        except Exception as exc:
            status.fail(f"Unable to finalize troubleshooting logs: {exc}")
            return 1
        status.ok(f"Troubleshooting logs written: {log_store.root}")
        if args.export_review_zip:
            status.stage("Exporting review ZIP")
            status.warn("Review ZIP contains private diagnostic material; review before sharing.")
            try:
                review_zip = export_review_zip(log_store)
            except Exception as exc:
                status.fail(f"Unable to export review ZIP: {exc}")
                return 1
            status.ok(f"Review ZIP written: {review_zip}")
    return 0


def _assessment_rules(technologies: Iterable[str]) -> list[HealthRule]:
    rules: list[HealthRule] = [
        ClusterIdentityRule(),
        NodeReachabilityRule(),
        CollectorHealthRule(),
        PlatformCheckSummaryRule(),
    ]
    for plugin in load_plugins(technologies):
        rules.extend(plugin.rules())
    return rules


def tls_policy_from_args(args: argparse.Namespace) -> TlsPolicy:
    verify = bool(args.verify_tls and not args.insecure)
    ca_bundle = Path(args.ca_bundle).expanduser() if args.ca_bundle else None
    return TlsPolicy(verify=verify, ca_bundle=ca_bundle)


def _write_html_report(
    report: AssessmentReport,
    requested_path: str | None,
    *,
    customer_safe: bool = False,
    template: str = "aletheiauc",
) -> Path:
    if requested_path:
        path = Path(requested_path).expanduser()
    else:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        path = Path("reports") / f"assessment-{timestamp}.html"

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        HtmlReportBuilder(customer_safe=customer_safe, template=template).build(report),
        encoding="utf-8",
    )
    return path


def _customer_safe_report_path(report_path: Path) -> Path:
    """Keep the review copy adjacent to, but distinct from, the selected report."""

    return report_path.with_name(f"{report_path.stem}-customer-safe{report_path.suffix}")


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
            "tool": "aletheiauc",
            "profile_name": profile_name,
            "publisher_ip": publisher_ip,
            "skipped_profile": skipped_profile,
            "artifact_redaction": artifact_redaction,
            "tls_verify": tls_verify,
            "tls_ca_bundle": tls_ca_bundle,
        }
    )


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
            "tool": "aletheiauc",
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
        transport_message = f"{interface.name} TCP reachability: {interface.endpoint}"
        if interface.transport_available:
            status.ok(transport_message)
        else:
            detail = f" - {interface.reason}" if interface.reason else ""
            status.warn(f"{transport_message}{detail}")

        if interface.wsdl_available is None:
            status.info(f"{interface.name} WSDL: scheduled for diagnostic collector")
        elif interface.wsdl_available:
            status.ok(f"{interface.name} WSDL: available")
        else:
            detail = f" - {interface.reason}" if interface.reason else ""
            status.warn(f"{interface.name} WSDL: unavailable{detail}")

        if interface.authenticated_available is None:
            if interface.name == "axl":
                status.info(f"{interface.name} authenticated operation: tested by collector")
            else:
                status.info(f"{interface.name} authenticated operation: scheduled for collector")
        elif interface.authenticated_available:
            status.ok(f"{interface.name} authenticated operation: available")
        else:
            detail = f" - {interface.reason}" if interface.reason else ""
            status.warn(f"{interface.name} authenticated operation: unavailable{detail}")

    if preflight.transport_available_interfaces:
        status.info("Enabled interfaces: " + ", ".join(preflight.transport_available_interfaces))


def _print_interface_validation_status(
    report: AssessmentReport,
    status: StatusPrinter,
) -> None:
    """Report observed WSDL and authenticated calls after collectors complete."""

    evidence = [item for result in report.collector_results for item in result.evidence]
    interfaces = sorted({item.source.lower() for item in evidence})
    if not interfaces:
        status.warn("Interface validation: no successful API evidence was recorded")
        return
    status.stage("Completed interface validation")
    for interface in interfaces:
        records = [item for item in evidence if item.source.lower() == interface]
        if any(item.operation == "wsdl" for item in records):
            status.ok(f"{interface} WSDL: captured")
        authenticated = [item for item in records if item.operation != "wsdl"]
        if authenticated:
            operations = ", ".join(sorted({item.operation for item in authenticated}))
            status.ok(f"{interface} authenticated read: {operations}")
