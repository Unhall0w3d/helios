"""Cisco Serviceability collector placeholder."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult


class ServiceabilityCollector:
    """Collects serviceability facts through Cisco serviceability APIs."""

    name = "serviceability"

    def collect(self, context: CollectionContext) -> CollectionResult:
        raise NotImplementedError("Serviceability collection is not implemented in the alpha skeleton.")
