"""AXL collector placeholder."""

from __future__ import annotations

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.facts import CollaborationNode


class AxlCollector:
    """Collects CUCM facts through the Publisher AXL API.

    The first real implementation target is cluster node discovery. It should
    connect to the Publisher using GUI/API credentials from ``CollectionContext``
    and populate normalized ``CollaborationNode`` facts for the Publisher and
    Subscribers before health rules run.
    """

    name = "axl"

    def collect(self, context: CollectionContext) -> CollectionResult:
        raise NotImplementedError("AXL collection is not implemented in the alpha skeleton.")

    def discover_nodes(self, context: CollectionContext) -> list[CollaborationNode]:
        """Discover Publisher and Subscriber nodes from Publisher API data."""

        raise NotImplementedError("AXL cluster node discovery is not implemented yet.")
