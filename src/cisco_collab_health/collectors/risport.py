"""RISPort collector placeholder."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult


class RisPortCollector:
    """Collects real-time CUCM facts through RISPort."""

    name = "risport"

    def collect(self, context: CollectionContext) -> CollectionResult:
        raise NotImplementedError("RISPort collection is not implemented in the alpha skeleton.")
