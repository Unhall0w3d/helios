"""AXL collector placeholder."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult


class AxlCollector:
    """Collects CUCM facts through the AXL API."""

    name = "axl"

    def collect(self, context: CollectionContext) -> CollectionResult:
        raise NotImplementedError("AXL collection is not implemented in the alpha skeleton.")
