"""AXL collector."""

from __future__ import annotations

from dataclasses import dataclass
import re
import xml.etree.ElementTree as ET

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, ClusterIdentity, CollaborationNode
from cisco_collab_health.transport.soap import (
    SoapClient,
    SoapHttpError,
    SoapRequest,
    SoapTransportError,
)

DEFAULT_AXL_VERSION = "14.0"
SUPPORTED_AXL_VERSIONS = ("15.0", "14.0", "12.5", "12.0", "11.5")
PSEUDO_PROCESS_NODE_NAMES = {"enterprisewidedata"}


@dataclass(frozen=True)
class AxlVersionPolicy:
    """Selects AXL schema versions supported by Helios."""

    preferred: str = DEFAULT_AXL_VERSION
    supported: tuple[str, ...] = SUPPORTED_AXL_VERSIONS

    def candidates(self, discovered_cucm_version: str | None = None) -> tuple[str, ...]:
        discovered = _major_minor(discovered_cucm_version) if discovered_cucm_version else None
        if discovered in self.supported:
            return (discovered, *tuple(version for version in self.supported if version != discovered))
        return (self.preferred, *tuple(version for version in self.supported if version != self.preferred))

    def best_supported_version(
        self,
        cucm_supported_versions: list[str],
        attempted_versions: set[str],
    ) -> str | None:
        normalized_supported = {_normalize_supported_version(version) for version in cucm_supported_versions}
        for version in self.supported:
            if version in attempted_versions:
                continue
            if version in normalized_supported:
                return version
        return None


class AxlCollector:
    """Collects CUCM facts through the Publisher AXL API.

    The first real implementation target is cluster node discovery. It should
    connect to the Publisher using GUI/API credentials from ``CollectionContext``
    and populate normalized ``CollaborationNode`` facts for the Publisher and
    Subscribers before health rules run.
    """

    name = "axl"

    def __init__(
        self,
        soap_client: SoapClient | None = None,
        version_policy: AxlVersionPolicy | None = None,
    ) -> None:
        self.soap_client = soap_client or SoapClient()
        self.version_policy = version_policy or AxlVersionPolicy()
        self._winning_axl_version: str | None = None

    def collect(self, context: CollectionContext) -> CollectionResult:
        warnings: list[str] = []
        facts = AssessmentFacts()

        if not context.publisher_ip:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=["AXL collection skipped because Publisher IP is missing."],
            )
        if not context.gui_username or not context.gui_password:
            return CollectionResult(
                collector_name=self.name,
                facts=facts,
                warnings=["AXL collection skipped because GUI/API credentials are missing."],
            )

        try:
            version_response = self._call_axl(context, "getCCMVersion", _get_ccm_version_body())
            version = _find_first_text(version_response, "version") or "unknown"
            facts.cluster = ClusterIdentity(
                name=context.publisher_ip,
                product="Cisco Unified Communications Manager",
                version=version,
            )
        except AxlCollectionError as exc:
            warnings.append(f"AXL getCCMVersion failed: {exc}")

        try:
            process_node_response = self._call_axl(
                context,
                "listProcessNode",
                _list_process_node_body(),
            )
            facts.nodes.extend(_parse_process_nodes(process_node_response, context.publisher_ip))
        except AxlCollectionError as exc:
            warnings.append(f"AXL listProcessNode failed: {exc}")

        if facts.cluster is not None and facts.nodes:
            facts.cluster = ClusterIdentity(
                name=_cluster_name_from_nodes(facts.nodes, context.publisher_ip),
                product=facts.cluster.product,
                version=facts.cluster.version,
            )

        return CollectionResult(
            collector_name=self.name,
            facts=facts,
            warnings=warnings,
        )

    def discover_nodes(self, context: CollectionContext) -> list[CollaborationNode]:
        """Discover Publisher and Subscriber nodes from Publisher API data."""

        response = self._call_axl(context, "listProcessNode", _list_process_node_body())
        return _parse_process_nodes(response, context.publisher_ip)

    def _call_axl(self, context: CollectionContext, operation: str, body: str) -> str:
        if not context.publisher_ip:
            raise AxlCollectionError("Publisher IP is missing.")
        if not context.gui_username or not context.gui_password:
            raise AxlCollectionError("GUI/API credentials are missing.")

        attempted_versions: set[str] = set()
        candidates = self.version_policy.candidates()
        if self._winning_axl_version is not None:
            candidates = (
                self._winning_axl_version,
                *tuple(version for version in candidates if version != self._winning_axl_version),
            )

        for axl_version in candidates:
            attempted_versions.add(axl_version)
            try:
                response = self._send_axl_request(context, operation, body, axl_version)
                self._winning_axl_version = axl_version
                return response
            except AxlVersionError as exc:
                retry_version = self.version_policy.best_supported_version(
                    exc.supported_versions,
                    attempted_versions,
                )
                if retry_version is None:
                    raise AxlCollectionError(str(exc)) from exc
                attempted_versions.add(retry_version)
                response = self._send_axl_request(
                    context,
                    operation,
                    body,
                    retry_version,
                    artifact_operation=f"{operation}_retry_axl_{retry_version}",
                )
                self._winning_axl_version = retry_version
                return response

        raise AxlCollectionError("No AXL schema versions are available to try.")

    def _send_axl_request(
        self,
        context: CollectionContext,
        operation: str,
        body: str,
        axl_version: str,
        *,
        artifact_operation: str | None = None,
    ) -> str:
        endpoint = f"https://{context.publisher_ip}:{context.axl_port}/axl/"
        request = SoapRequest(
            endpoint,
            body=body,
            namespace=f"http://www.cisco.com/AXL/API/{axl_version}",
            operation=operation,
            interface="axl",
            node=context.publisher_ip,
            action=f'CUCM:DB ver={axl_version} "{operation}"',
            artifact_operation=artifact_operation,
        )

        try:
            return self.soap_client.send(request, context).body
        except SoapHttpError as exc:
            supported_versions = _supported_axl_versions(exc.body)
            if _is_incorrect_axl_version_response(exc.body) and supported_versions:
                raise AxlVersionError(
                    attempted_version=axl_version,
                    supported_versions=supported_versions,
                    response_summary=_response_summary(exc.body),
                ) from exc
            raise AxlCollectionError(f"HTTP {exc.status}: {_response_summary(exc.body)}") from exc
        except SoapTransportError as exc:
            raise AxlCollectionError(str(exc)) from exc


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


def _get_ccm_version_body() -> str:
    return "<axl:getCCMVersion />"


def _list_process_node_body() -> str:
    return """<axl:listProcessNode>
      <searchCriteria>
        <name>%</name>
      </searchCriteria>
      <returnedTags>
        <name />
        <description />
        <nodeUsage />
      </returnedTags>
    </axl:listProcessNode>"""


def _parse_process_nodes(response_text: str, publisher_ip: str | None) -> list[CollaborationNode]:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse listProcessNode response: {exc}") from exc
    nodes: list[CollaborationNode] = []
    for process_node in _iter_local_name(root, "processNode"):
        name = _child_text(process_node, "name")
        if not name:
            continue
        if _is_pseudo_process_node(name):
            continue
        node_usage = (_child_text(process_node, "nodeUsage") or "").lower()
        role = "publisher" if publisher_ip and name == publisher_ip else "subscriber"
        if "publisher" in node_usage:
            role = "publisher"
        elif "subscriber" in node_usage:
            role = "subscriber"
        nodes.append(
            CollaborationNode(
                name=name,
                address=name,
                role=role,
                reachable=None,
            )
        )
    return nodes


def _is_pseudo_process_node(name: str) -> bool:
    return name.strip().lower() in PSEUDO_PROCESS_NODE_NAMES


def _cluster_name_from_nodes(nodes: list[CollaborationNode], publisher_ip: str) -> str:
    publisher = next((node for node in nodes if node.role == "publisher"), None)
    if publisher:
        return publisher.name
    return publisher_ip


def _find_first_text(response_text: str, local_name: str) -> str | None:
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise AxlCollectionError(f"Unable to parse AXL response: {exc}") from exc
    element = next(_iter_local_name(root, local_name), None)
    if element is None or element.text is None:
        return None
    return element.text.strip()


def _child_text(element: ET.Element, local_name: str) -> str | None:
    child = next(_iter_local_name(element, local_name), None)
    if child is None or child.text is None:
        return None
    return child.text.strip()


def _iter_local_name(element: ET.Element, local_name: str):
    for child in element.iter():
        if child.tag.rsplit("}", 1)[-1] == local_name:
            yield child


def _response_summary(response_text: str) -> str:
    stripped = " ".join(response_text.split())
    return stripped[:300]


def _is_incorrect_axl_version_response(response_text: str) -> bool:
    return "incorrect axl version" in response_text.lower()


def _supported_axl_versions(response_text: str) -> list[str]:
    match = re.search(
        r"Supported\s+axl\s+versions\s+are\s+(.+?)(?:<|\n|$)",
        response_text,
        flags=re.IGNORECASE,
    )
    if match is None:
        return []
    version_text = match.group(1)
    return re.findall(r"\d+(?:\.\d+)?(?:\.x)?", version_text)


def _highest_version(versions: list[str]) -> str:
    return max(versions, key=_version_sort_key)


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None
    match = re.match(r"^\s*(\d+)\.(\d+)", version)
    if match is None:
        return None
    return f"{match.group(1)}.{match.group(2)}"


def _normalize_supported_version(version: str) -> str:
    normalized = version.strip().lower()
    if normalized.endswith(".x"):
        return normalized.replace(".x", ".0")
    return normalized


def _version_sort_key(version: str) -> tuple[int, ...]:
    normalized = version.lower().replace(".x", ".0")
    return tuple(int(part) for part in normalized.split(".") if part.isdigit())
