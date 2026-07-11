"""Display formatting helpers for human-readable reports."""

from __future__ import annotations

import re


STATUS_LABELS = {
    "collected": "Collected",
    "empty": "Empty",
    "not_collected": "Not collected",
    "not_implemented": "Not implemented",
    "skipped": "Skipped",
}

SOURCE_LABELS = {
    "AXL": "AXL",
    "AXL.listPhone.summary": "AXL – Phone inventory",
    "AXL.listDevicePool": "AXL – Device pool",
    "AXL.listDeviceDefaults": "AXL – Device defaults",
    "AXL.getDeviceDefaults": "AXL – Device defaults",
    "AXL.executeSQLQuery.deviceDefaults": "AXL – Device defaults",
    "RISPort70": "RISPort",
    "RISPort70.selectCmDeviceExt": "RISPort – Device registration",
    "RISPort70.selectCmDevice": "RISPort – Device registration",
    "ControlCenter": "Control Center",
    "ControlCenter.soapGetServiceStatus": "Control Center – Service status",
    "PerfMon": "PerfMon",
    "PerfMon.perfmonCollectCounterData": "PerfMon – Performance counters",
    "normalized_facts": "Normalized assessment data",
    "collector_result": "Collector result",
    "sample.synthetic": "Sample data",
}


def display_text(value: object | None, *, empty: str = "—") -> str:
    """Return a report-friendly string for optional values."""

    if value is None:
        return empty
    text = str(value).strip()
    return text or empty


def display_bool(value: bool | None) -> str:
    """Return a report-friendly string for optional booleans."""

    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return display_text(None)


def display_status_label(value: str) -> str:
    """Return a report-friendly label for internal status values."""

    return STATUS_LABELS.get(value, value.replace("_", " ").capitalize())


def display_details(details: dict[str, str]) -> str:
    """Return a stable key/value rendering for details dictionaries."""

    if not details:
        return display_text(None)
    rendered = [
        f"{key}: {value}"
        for key, value in sorted(details.items())
        if str(value).strip()
    ]
    if not rendered:
        return display_text(None)
    return "; ".join(rendered)


def display_duration(seconds: int | None) -> str:
    """Render an optional non-negative duration in human-readable units."""

    if seconds is None or seconds < 0:
        return display_text(None)
    if seconds < 60:
        return "Less than 1 minute" if seconds else "0 minutes"

    remaining_minutes = seconds // 60
    years, remaining_minutes = divmod(remaining_minutes, 365 * 24 * 60)
    days, remaining_minutes = divmod(remaining_minutes, 24 * 60)
    hours, minutes = divmod(remaining_minutes, 60)
    parts = [
        _duration_part(years, "year"),
        _duration_part(days, "day"),
        _duration_part(hours, "hour"),
        _duration_part(minutes, "minute"),
    ]
    return ", ".join(part for part in parts if part)


def display_source(value: str | None) -> str:
    """Render internal provenance identifiers as report-friendly source labels."""

    if not value or not value.strip():
        return display_text(None)
    sources = [source.strip() for source in value.split(",") if source.strip()]
    return "; ".join(SOURCE_LABELS.get(source, _humanize_source(source)) for source in sources)


def _duration_part(value: int, unit: str) -> str:
    if not value:
        return ""
    suffix = "" if value == 1 else "s"
    return f"{value} {unit}{suffix}"


def _humanize_source(value: str) -> str:
    components = value.split(".")
    return " – ".join(_humanize_identifier(component) for component in components)


def _humanize_identifier(value: str) -> str:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value.replace("_", " "))
    return spaced[:1].upper() + spaced[1:]
