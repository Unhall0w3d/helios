"""CLI fallback collector placeholder."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult


class CliCollector:
    """Collects facts through SSH/CLI when APIs cannot provide required data."""

    name = "cli"

    def collect(self, context: CollectionContext) -> CollectionResult:
        raise NotImplementedError("CLI fallback collection is not implemented in the alpha skeleton.")
