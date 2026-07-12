"""Read-only Cisco Unity Connection collection foundation."""

from __future__ import annotations

import json

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import AssessmentFacts, ClusterIdentity, ConfigurationObjectFact
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpClient, CapturedHttpError


class CucCollector:
    """Establish CUPI connectivity and collect a bounded mailbox count."""

    name = "cuc"

    def __init__(self, http_client: CapturedHttpClient | None = None) -> None:
        self.http_client = http_client or CapturedHttpClient()

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        evidence: list[EvidenceRef] = []
        notes = [
            "Unity Connection CUPI foundation enabled; collection is read-only and bounded.",
            "Platform/SSH credentials remain available for future CUC CLI collectors.",
        ]
        node = context.publisher_ip or context.target
        if not node:
            return CollectionResult(self.name, facts, warnings=["CUC target is missing."])
        endpoint = f"https://{node}/vmrest/users?rowsPerPage=1&pageNumber=1"
        try:
            response = self.http_client.get(
                endpoint, context, node=node, interface="cuc_cupi",
                operation="users_bounded_probe",
            )
        except CapturedHttpError as exc:
            warnings.append(f"CUC CUPI bounded user probe failed: {exc}")
            return CollectionResult(self.name, facts, warnings=warnings, notes=notes)
        evidence.append(EvidenceRef(
            source="CUC.CUPI", operation="users_bounded_probe", node=node,
            artifact_path=response.response_artifact_path, confidence="high",
        ))
        total = _cupi_total(response.body)
        facts.cluster = ClusterIdentity(
            name=node, product="Cisco Unity Connection", version="unknown",
        )
        facts.configuration_objects.append(ConfigurationObjectFact(
            object_type="CucMailboxInventory", name="Users",
            details={"total": str(total) if total is not None else "unknown", "requested_rows": "1"},
            source="CUC.CUPI.users",
        ))
        return CollectionResult(self.name, facts, warnings=warnings, evidence=evidence, notes=notes)


def _cupi_total(payload: str) -> int | None:
    """Read the CUPI collection total from JSON or XML without retaining user detail."""

    try:
        document = json.loads(payload)
        for key in ("total", "Total", "@total"):
            if key in document:
                return int(document[key])
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    try:
        root = ET.fromstring(payload)
        value = root.attrib.get("total") or root.attrib.get("Total")
        return int(value) if value is not None else None
    except (ET.ParseError, ValueError):
        return None
