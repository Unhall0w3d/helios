"""Collection interfaces and implementations."""

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult, Collector
from cisco_collab_health.collectors.cluster import ClusterNodeDiscoveryCollector

__all__ = [
    "ClusterNodeDiscoveryCollector",
    "CollectionContext",
    "CollectionResult",
    "Collector",
]
