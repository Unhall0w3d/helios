"""Normalized facts collected from Cisco Collaboration systems."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClusterIdentity:
    """Basic identity facts for a CUCM or SME cluster."""

    name: str
    product: str
    version: str


@dataclass(frozen=True)
class CollaborationNode:
    """Basic node facts normalized across collection sources."""

    name: str
    address: str
    role: str
    reachable: bool | None = None


@dataclass
class AssessmentFacts:
    """Container for normalized assessment facts."""

    cluster: ClusterIdentity | None = None
    nodes: list[CollaborationNode] = field(default_factory=list)

    def merge(self, other: "AssessmentFacts") -> None:
        """Merge another facts object into this one."""

        if other.cluster is not None:
            self.cluster = other.cluster
        self.nodes.extend(other.nodes)
