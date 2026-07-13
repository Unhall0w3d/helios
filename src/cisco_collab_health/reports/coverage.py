"""Report collection coverage helpers."""

from __future__ import annotations

from dataclasses import dataclass

from cisco_collab_health.models.assessment import AssessmentReport


@dataclass(frozen=True)
class ReportCoverageItem:
    """Human-readable coverage status for one report area."""

    name: str
    status: str
    count: int
    detail: str


def build_report_coverage(report: AssessmentReport) -> list[ReportCoverageItem]:
    """Build conservative report coverage rows from normalized facts and metadata."""

    note_count = sum(len(result.notes) for result in report.collector_results)
    evidence_count = sum(len(result.evidence) for result in report.collector_results)
    issue_count = sum(
        len(result.warnings) + len(result.errors) for result in report.collector_results
    )
    collection_ran = bool(report.collector_results)

    return [
        _cluster_coverage(report),
        _count_coverage(
            "Cluster nodes",
            len(report.facts.nodes),
            collection_ran=collection_ran,
            collected_detail="Node inventory was normalized.",
            empty_detail="Collection ran but no cluster nodes were normalized.",
            not_collected_detail="No node inventory collection result is available.",
        ),
        _device_coverage(report, collection_ran),
        _device_load_defaults_coverage(report, collection_ran),
        _cuc_inventory_coverage(report, collection_ran),
        _cuc_configuration_coverage(report, collection_ran),
        _count_coverage(
            "Configuration inventory",
            len(report.facts.configuration_objects),
            collection_ran=collection_ran,
            collected_detail="Bounded AXL/CUPI configuration objects were normalized.",
            empty_detail="Collection ran but no configuration objects were normalized.",
            not_collected_detail="No configuration inventory collection result is available.",
        ),
        _not_yet_implemented_coverage(
            "Device registration",
            len(report.facts.registrations),
            "RISPort70 collector is not implemented yet.",
        ),
        _not_yet_implemented_coverage(
            "Services",
            len(report.facts.services),
            "Control Center collector is not implemented yet.",
        ),
        _not_yet_implemented_coverage(
            "Performance counters",
            len(report.facts.perf_counters),
            "PerfMon collector is not implemented yet.",
        ),
        _not_yet_implemented_coverage(
            "Platform checks",
            len(report.facts.platform_checks),
            "CLI/platform collector is not implemented yet.",
        ),
        ReportCoverageItem(
            name="Collector issues",
            status="collected" if issue_count else "empty",
            count=issue_count,
            detail=(
                "Collector warnings or errors were recorded."
                if issue_count
                else "No collector warnings or errors were recorded."
            ),
        ),
        ReportCoverageItem(
            name="Collector notes",
            status="collected" if note_count else "empty",
            count=note_count,
            detail=(
                "Collector operational notes were recorded."
                if note_count
                else "No collector operational notes were recorded."
            ),
        ),
        ReportCoverageItem(
            name="Collector evidence",
            status="collected" if evidence_count else "empty",
            count=evidence_count,
            detail=(
                "Collector evidence references were recorded."
                if evidence_count
                else "No collector evidence references were recorded."
            ),
        ),
        ReportCoverageItem(
            name="Findings",
            status="collected" if report.findings else "empty",
            count=len(report.findings),
            detail=(
                "Health rules generated findings."
                if report.findings
                else "Health rules generated no findings."
            ),
        ),
    ]


def _cluster_coverage(report: AssessmentReport) -> ReportCoverageItem:
    if report.facts.cluster is not None:
        return ReportCoverageItem(
            name="Cluster identity",
            status="collected",
            count=1,
            detail="Cluster identity facts are present.",
        )
    return ReportCoverageItem(
        name="Cluster identity",
        status="not_collected",
        count=0,
        detail="Cluster identity facts are not present.",
    )


def _device_coverage(report: AssessmentReport, collection_ran: bool) -> ReportCoverageItem:
    device_count = len(report.facts.devices)
    if device_count:
        return ReportCoverageItem(
            name="Device inventory",
            status="collected",
            count=device_count,
            detail="Device inventory facts were normalized.",
        )

    if _has_status_flag(report, "axl.phone_inventory.skipped"):
        return ReportCoverageItem(
            name="Device inventory",
            status="skipped",
            count=0,
            detail="AXL phone inventory was skipped by collection scope.",
        )

    return _count_coverage(
        "Device inventory",
        device_count,
        collection_ran=collection_ran,
        collected_detail="Device inventory facts were normalized.",
        empty_detail="Collection ran but no device inventory facts were normalized.",
        not_collected_detail="No device inventory collection result is available.",
    )


def _device_load_defaults_coverage(
    report: AssessmentReport,
    collection_ran: bool,
) -> ReportCoverageItem:
    default_count = len(report.facts.device_load_defaults)
    if default_count:
        return ReportCoverageItem(
            name="Device load defaults",
            status="collected",
            count=default_count,
            detail="Device default load facts were normalized.",
        )
    if _has_status_flag(report, "axl.phone_inventory.skipped"):
        return ReportCoverageItem(
            name="Device load defaults",
            status="skipped",
            count=0,
            detail="AXL device defaults were skipped because phone inventory scope was skipped.",
        )
    return _count_coverage(
        "Device load defaults",
        default_count,
        collection_ran=collection_ran,
        collected_detail="Device default load facts were normalized.",
        empty_detail="Collection ran but no device default load facts were normalized.",
        not_collected_detail="No device default load collection result is available.",
    )


def _cuc_inventory_coverage(
    report: AssessmentReport, collection_ran: bool
) -> ReportCoverageItem:
    inventory_types = {
        item.object_type
        for item in report.facts.configuration_objects
        if item.source.startswith("CUC.CUPI") and item.object_type.endswith("Inventory")
    }
    return _count_coverage(
        "Unity Connection inventory",
        len(inventory_types),
        collection_ran=collection_ran,
        collected_detail="Bounded CUPI inventory counts were normalized by object type.",
        empty_detail="Collection ran but no Unity Connection CUPI inventory was normalized.",
        not_collected_detail="No Unity Connection CUPI inventory collection result is available.",
    )


def _cuc_configuration_coverage(
    report: AssessmentReport, collection_ran: bool
) -> ReportCoverageItem:
    configuration_types = {
        item.object_type
        for item in report.facts.configuration_objects
        if item.source.startswith("CUC.CUPI") and not item.object_type.endswith("Inventory")
    }
    return _count_coverage(
        "Unity Connection configuration",
        len(configuration_types),
        collection_ran=collection_ran,
        collected_detail="Sanitized CUPI configuration records were normalized by object type.",
        empty_detail="Collection ran but no detailed Unity Connection configuration was normalized.",
        not_collected_detail="No detailed Unity Connection CUPI configuration result is available.",
    )


def _not_yet_implemented_coverage(
    name: str,
    count: int,
    not_implemented_detail: str,
) -> ReportCoverageItem:
    if count:
        return ReportCoverageItem(
            name=name,
            status="collected",
            count=count,
            detail=f"{name} facts were normalized.",
        )
    return ReportCoverageItem(
        name=name,
        status="not_implemented",
        count=0,
        detail=not_implemented_detail,
    )


def _count_coverage(
    name: str,
    count: int,
    *,
    collection_ran: bool,
    collected_detail: str,
    empty_detail: str,
    not_collected_detail: str,
) -> ReportCoverageItem:
    if count:
        return ReportCoverageItem(
            name=name,
            status="collected",
            count=count,
            detail=collected_detail,
        )
    if collection_ran:
        return ReportCoverageItem(
            name=name,
            status="empty",
            count=0,
            detail=empty_detail,
        )
    return ReportCoverageItem(
        name=name,
        status="not_collected",
        count=0,
        detail=not_collected_detail,
    )


def _has_status_flag(report: AssessmentReport, flag: str) -> bool:
    return any(
        flag == status_flag
        for result in report.collector_results
        for status_flag in result.status_flags
    )
