"""AXL collector error types."""

from __future__ import annotations


class AxlCollectionError(RuntimeError):
    """Raised when an AXL collection operation fails."""


class AxlVersionError(AxlCollectionError):
    """Raised when CUCM rejects the requested AXL schema version."""

    def __init__(
        self,
        *,
        attempted_version: str,
        supported_versions: list[str],
        response_summary: str,
    ) -> None:
        self.attempted_version = attempted_version
        self.supported_versions = supported_versions
        self.highest_supported_version = _highest_version(supported_versions)
        super().__init__(
            "Incorrect AXL version "
            f"{attempted_version}; retrying with {self.highest_supported_version}. "
            f"Response: {response_summary}"
        )


def _highest_version(versions: list[str]) -> str:
    return max(versions, key=_version_sort_key)


def _version_sort_key(version: str) -> tuple[int, ...]:
    normalized = version.lower().replace(".x", ".0")
    return tuple(int(part) for part in normalized.split(".") if part.isdigit())
