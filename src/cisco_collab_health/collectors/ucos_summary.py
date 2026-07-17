"""Shared parsers for read-only UCOS platform command output."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime


def version_summary(output: str, *, active: bool) -> dict[str, str]:
    """Normalize a UCOS active/inactive version and installed software options."""

    state = "Active" if active else "Inactive"
    key = "active_version" if active else "inactive_version"
    match = re.search(rf"(?im)^{state} Master Version:\s*(\S+)", output)
    summary = {key: match.group(1) if match else "unknown"}
    if active:
        options_match = re.search(
            r"(?ims)^Active Version Installed Software Options:\s*(.*)$", output
        )
        option_text = options_match.group(1) if options_match else ""
        options = [
            line.strip()
            for line in option_text.splitlines()
            if line.strip() and "no installed software options found" not in line.lower()
        ]
        summary["installed_software_options"] = "|".join(options)
    return summary


def disk_usage_summary(output: str) -> dict[str, str]:
    """Extract explicit UCOS active and common/logging partition utilization."""

    partitions = {
        match.group("partition").lower(): int(match.group("usage"))
        for match in re.finditer(
            r"(?im)^Disk/(?P<partition>\S+).*?\((?P<usage>\d+)%\)", output
        )
    }
    values = list(partitions.values())
    summary = {
        "max_disk_usage_percent": str(max(values)) if values else "unknown",
        "active_partition_usage_percent": str(partitions.get("active", "unknown")),
        "common_partition_usage_percent": str(partitions.get("logging", "unknown")),
        "disk_warning_count": str(sum(value >= 90 for value in values)),
        "disk_critical_count": str(sum(value >= 95 for value in values)),
    }
    return summary


def drs_backup_summary(output: str, *, today: date | None = None) -> dict[str, str]:
    """Summarize explicitly successful DRS history rows without guessing dates."""

    successes = re.findall(r"\bSUCCESS\b", output, re.I)
    unavailable = bool(
        re.search(
            r"master agent.*(?:down|processing)|network request timed out|error occurred",
            output,
            re.I,
        )
    )
    summary = {
        "successful_backup_entries": str(len(successes)),
        "drs_unavailable": str(unavailable).lower(),
    }
    latest = _latest_successful_backup(output)
    if latest is not None:
        reference_date = today or datetime.now(UTC).date()
        summary["latest_successful_backup"] = latest.isoformat()
        summary["latest_successful_backup_age_days"] = str(
            max(0, (reference_date - latest).days)
        )
    return summary


def _latest_successful_backup(output: str) -> date | None:
    """Parse common ISO/U.S. successful DRS backup-history dates only."""

    candidates: list[datetime] = []
    for line in output.splitlines():
        if not re.search(r"\bSUCCESS\b", line, re.I):
            continue
        iso = re.search(r"\b(20\d{2}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?\b", line)
        if iso:
            value = f"{iso.group(1)} {iso.group(2) or '00:00:00'}"
            try:
                candidates.append(datetime.strptime(value, "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                pass
            continue
        us = re.search(r"\b(\d{1,2}/\d{1,2}/20\d{2})(?:\s+(\d{2}:\d{2}:\d{2}))?\b", line)
        if us:
            value = f"{us.group(1)} {us.group(2) or '00:00:00'}"
            try:
                candidates.append(datetime.strptime(value, "%m/%d/%Y %H:%M:%S"))
            except ValueError:
                pass
    return max(candidates).date() if candidates else None
