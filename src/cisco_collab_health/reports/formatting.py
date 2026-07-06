"""Display formatting helpers for human-readable reports."""

from __future__ import annotations


STATUS_LABELS = {
    "collected": "Collected",
    "empty": "Empty",
    "not_collected": "Not collected",
    "not_implemented": "Not implemented",
    "skipped": "Skipped",
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
