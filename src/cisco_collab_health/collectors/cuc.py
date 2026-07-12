"""Read-only Cisco Unity Connection collection foundation."""

from __future__ import annotations

import json

from defusedxml import ElementTree as ET

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.evidence import EvidenceRef
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    ConfigurationObjectFact,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.http import CapturedHttpClient, CapturedHttpError


class CucCollector:
    """Read-only bounded CUPI inventory and configuration collection."""

    name = "cuc"

    def __init__(
        self,
        http_client: CapturedHttpClient | None = None,
        *,
        diagnostic_capture: bool = False,
    ) -> None:
        self.http_client = http_client or CapturedHttpClient()
        self.diagnostic_capture = diagnostic_capture

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        evidence: list[EvidenceRef] = []
        notes = [
            "Unity Connection CUPI collection uses bounded, read-only GET requests.",
        ]
        node = context.publisher_ip or context.target
        if not node:
            return CollectionResult(self.name, facts, warnings=["CUC target is missing."])
        facts.cluster = ClusterIdentity(
            name=node,
            product="Cisco Unity Connection",
            version="unknown",
        )
        probes = [("CucMailboxInventory", "Mailboxes", "/vmrest/users")]
        if self.diagnostic_capture:
            probes.extend(
                [
                    ("CucContactInventory", "Contacts", "/vmrest/contacts"),
                    (
                        "CucDistributionListInventory",
                        "Distribution lists",
                        "/vmrest/distributionlists",
                    ),
                    ("CucCallHandlerInventory", "Call handlers", "/vmrest/handlers/callhandlers"),
                    ("CucClassOfServiceInventory", "Classes of service", "/vmrest/coses"),
                    (
                        "CucConfigurationValueInventory",
                        "System configuration values",
                        "/vmrest/configurationvalues",
                    ),
                ]
            )
        for object_type, name, path in probes:
            endpoint = f"https://{node}{path}?rowsPerPage=1&pageNumber=1"
            operation = f"{object_type}_bounded_probe"
            try:
                response = self.http_client.get(
                    endpoint,
                    context,
                    node=node,
                    interface="cuc_cupi",
                    operation=operation,
                )
            except CapturedHttpError as exc:
                warnings.append(f"CUC CUPI {name.lower()} probe failed: {exc}")
                continue
            evidence.append(
                EvidenceRef(
                    source="CUC.CUPI",
                    operation=operation,
                    node=node,
                    artifact_path=response.response_artifact_path,
                    confidence="high",
                )
            )
            total = _cupi_total(response.body)
            facts.configuration_objects.append(
                ConfigurationObjectFact(
                    object_type=object_type,
                    name=name,
                    details={
                        "total": str(total) if total is not None else "unknown",
                        "requested_rows": "1",
                    },
                    source=f"CUC.CUPI{path}",
                )
            )
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
