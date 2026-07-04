"""AXL schema version policy and response helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re

DEFAULT_AXL_VERSION = "14.0"
SUPPORTED_AXL_VERSIONS = ("15.0", "14.0", "12.5", "12.0", "11.5")


@dataclass(frozen=True)
class AxlVersionPolicy:
    """Selects AXL schema versions supported by Helios."""

    preferred: str = DEFAULT_AXL_VERSION
    supported: tuple[str, ...] = SUPPORTED_AXL_VERSIONS

    def candidates(self, discovered_cucm_version: str | None = None) -> tuple[str, ...]:
        discovered = _major_minor(discovered_cucm_version) if discovered_cucm_version else None
        if discovered in self.supported:
            return (
                discovered,
                *tuple(version for version in self.supported if version != discovered),
            )
        return (
            self.preferred,
            *tuple(version for version in self.supported if version != self.preferred),
        )

    def best_supported_version(
        self,
        cucm_supported_versions: list[str],
        attempted_versions: set[str],
    ) -> str | None:
        normalized_supported = {
            _normalize_supported_version(version) for version in cucm_supported_versions
        }
        for version in self.supported:
            if version in attempted_versions:
                continue
            if version in normalized_supported:
                return version
        return None


def response_summary(response_text: str) -> str:
    stripped = " ".join(response_text.split())
    return stripped[:300]


def is_incorrect_axl_version_response(response_text: str) -> bool:
    return "incorrect axl version" in response_text.lower()


def supported_axl_versions(response_text: str) -> list[str]:
    match = re.search(
        r"Supported\s+axl\s+versions\s+are\s+(.+?)(?:<|\n|$)",
        response_text,
        flags=re.IGNORECASE,
    )
    if match is None:
        return []
    version_text = match.group(1)
    return re.findall(r"\d+(?:\.\d+)?(?:\.x)?", version_text)


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None
    match = re.match(r"^\s*(\d+)\.(\d+)", version)
    if match is None:
        return None
    return f"{match.group(1)}.{match.group(2)}"


def _normalize_supported_version(version: str) -> str:
    normalized = version.strip().lower()
    if normalized.endswith(".x"):
        return normalized.replace(".x", ".0")
    return normalized
