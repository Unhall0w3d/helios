"""Curated Cisco UC application lifecycle records used for report evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class LifecycleRecord:
    technology: str
    release: str
    end_of_sale: date | None
    end_of_maintenance: date | None
    last_support: date | None
    source_url: str | None
    notice_available: bool = True


@dataclass(frozen=True)
class LifecycleStatus:
    """A plain-language lifecycle evaluation for a known Cisco release."""

    label: str
    detail: str
    attention_needed: bool


_COMMON_115 = "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-744533.html"
_COMMON_125 = "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/v-12-5-on-premises-calling-applications-eol.html"
_COMMON_14 = "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/v-14-premises-flex-subscriptions-eol.html"

_RECORDS = (
    LifecycleRecord("cucm", "10", date(2019, 7, 2), date(2020, 7, 1), date(2022, 7, 31), "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-741767.html"),
    LifecycleRecord("cuc", "10", date(2019, 7, 2), date(2020, 7, 1), date(2022, 7, 31), "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unity-connection/eos-eol-notice-c51-741765.html"),
    LifecycleRecord("cer", "10", date(2019, 7, 2), date(2020, 7, 1), date(2022, 7, 31), "https://www.cisco.com/c/en/us/products/collateral/unified-communications/emergency-responder/eos-eol-notice-c51-741766.html"),
    *(
        LifecycleRecord(technology, "11.5", date(2021, 5, 31), date(2022, 5, 31), date(2024, 5, 31), _COMMON_115)
        for technology in ("cucm", "cuc", "cer", "imp")
    ),
    LifecycleRecord("cucm", "12.0", date(2020, 8, 17), date(2021, 8, 17), date(2023, 8, 31), "https://www.cisco.com/c/en/us/products/collateral/unified-communications/unified-communications-manager-callmanager/eos-eol-notice-c51-743485.html"),
    LifecycleRecord("cer", "12.0", date(2020, 8, 17), date(2021, 8, 17), date(2023, 8, 31), "https://www.cisco.com/c/en/us/products/collateral/unified-communications/emergency-responder/eos-eol-notice-c51-743484.html"),
    *(
        LifecycleRecord(technology, "12.5", date(2023, 8, 31), date(2024, 8, 31), date(2025, 8, 31), _COMMON_125)
        for technology in ("cucm", "cuc", "cer", "imp")
    ),
    *(
        LifecycleRecord(technology, "14", date(2025, 4, 7), date(2026, 4, 7), date(2027, 4, 30), _COMMON_14)
        for technology in ("cucm", "cuc", "cer", "imp")
    ),
    # Version 15 is a current release family. Keep this explicit local state so
    # reports do not imply it is unassessed or supported indefinitely while Cisco
    # has not published its lifecycle notice.
    *(
        LifecycleRecord(technology, "15", None, None, None, None, notice_available=False)
        for technology in ("cucm", "cuc", "cer", "imp")
    ),
)

_BY_KEY = {(item.technology, item.release): item for item in _RECORDS}


def lifecycle_for(technology: str, version: str) -> LifecycleRecord | None:
    """Return an exact catalog match; unknown versions are intentionally not inferred."""

    # Cisco version text can be a full build (``10.5.2.12901-1``) or a
    # maintenance label (``v10SU3``).  Major-version notices intentionally
    # apply to every 10.x maintenance release unless a more-specific catalog
    # record exists.
    match = re.match(r"\s*v?(\d+)(?:\.(\d+))?", version, flags=re.IGNORECASE)
    if not match:
        return None
    major, minor = match.groups()
    for release in (f"{major}.{minor}" if minor else major, major):
        if record := _BY_KEY.get((technology.lower(), release)):
            return record
    return None


def technology_for_product(product: str) -> str | None:
    """Map normalized Cisco product text to the assessment technology key."""

    normalized = product.casefold()
    if "unity connection" in normalized:
        return "cuc"
    if "emergency responder" in normalized:
        return "cer"
    if "im and presence" in normalized or "im&p" in normalized:
        return "imp"
    if "callmanager" in normalized or "unified communications manager" in normalized:
        return "cucm"
    return None


def lifecycle_status(record: LifecycleRecord, *, as_of: date | None = None) -> LifecycleStatus:
    """Evaluate a catalog record without guessing for releases outside the catalog."""

    if not record.notice_available:
        return LifecycleStatus(
            "End of sale / end of life / end of support not yet available",
            "Cisco has not yet published lifecycle dates for this major release.",
            False,
        )

    assert record.end_of_sale is not None
    assert record.end_of_maintenance is not None
    assert record.last_support is not None
    today = as_of or date.today()
    if today > record.last_support:
        return LifecycleStatus(
            "Cisco support ended",
            f"Last date of support was {record.last_support.isoformat()}.",
            True,
        )
    if today > record.end_of_maintenance:
        return LifecycleStatus(
            "Cisco software maintenance ended",
            f"Software maintenance ended {record.end_of_maintenance.isoformat()}; "
            f"last support is {record.last_support.isoformat()}.",
            True,
        )
    days_to_support_end = (record.last_support - today).days
    if days_to_support_end <= 180:
        return LifecycleStatus(
            "Cisco support ending soon",
            f"Last support is {record.last_support.isoformat()} ({days_to_support_end} days).",
            True,
        )
    if today > record.end_of_sale:
        return LifecycleStatus(
            "Past Cisco end of sale",
            f"End of sale was {record.end_of_sale.isoformat()}; "
            f"last support is {record.last_support.isoformat()}.",
            False,
        )
    return LifecycleStatus(
        "Within recorded lifecycle dates",
        f"Last support is {record.last_support.isoformat()}.",
        False,
    )
