"""AXL collector."""

from __future__ import annotations

import base64
import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from cisco_collab_health.collectors.base import CollectionContext, CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, ClusterIdentity, CollaborationNode

DEFAULT_AXL_VERSION = "14.0"
SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
PSEUDO_PROCESS_NODE_NAMES = {"enterprisewidedata"}


class AxlCollector:
    """Collects CUCM facts through the Publisher AXL API.

    The first real implementation target is cluster node discovery. It should
    connect to the Publisher using GUI/API credentials from ``CollectionContext``
    and populate normalized ``CollaborationNode`` facts for the Publisher and
    Subscribers before health rules run.
    """

    name = "axl"

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

        axl_version = DEFAULT_AXL_VERSION
        try:
            return self._send_axl_request(context, operation, body, axl_version)
        except AxlVersionError as exc:
            retry_version = exc.highest_supported_version
            if retry_version == axl_version:
                raise AxlCollectionError(str(exc)) from exc
            return self._send_axl_request(
                context,
                operation,
                body,
                retry_version,
                artifact_operation=f"{operation}_retry_axl_{retry_version}",
            )

    def _send_axl_request(
        self,
        context: CollectionContext,
        operation: str,
        body: str,
        axl_version: str,
        *,
        artifact_operation: str | None = None,
    ) -> str:
        envelope = _soap_envelope(body, axl_version)
        endpoint = f"https://{context.publisher_ip}:{context.axl_port}/axl/"
        credentials = f"{context.gui_username}:{context.gui_password}".encode("utf-8")
        request_headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'CUCM:DB ver={axl_version} "{operation}"',
        }
        request_artifact = _format_http_request(
            endpoint,
            headers=request_headers,
            body=envelope,
        )
        request = urllib.request.Request(
            endpoint,
            data=envelope.encode("utf-8"),
            headers={
                "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
                **request_headers,
            },
            method="POST",
        )

        try:
            ssl_context = ssl._create_unverified_context()
            with urllib.request.urlopen(
                request,
                timeout=context.timeout_seconds,
                context=ssl_context,
            ) as response:
                response_text = response.read().decode("utf-8", errors="replace")
                response_artifact = _format_http_response(
                    status=getattr(response, "status", None),
                    reason=getattr(response, "reason", None),
                    headers=getattr(response, "headers", None),
                    body=response_text,
                )
        except urllib.error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            response_artifact = _format_http_response(
                status=exc.code,
                reason=exc.reason,
                headers=exc.headers,
                body=response_text,
            )
            _write_api_artifact(
                context,
                context.publisher_ip,
                artifact_operation or operation,
                request_artifact,
                response_artifact,
            )
            supported_versions = _supported_axl_versions(response_text)
            if _is_incorrect_axl_version_response(response_text) and supported_versions:
                raise AxlVersionError(
                    attempted_version=axl_version,
                    supported_versions=supported_versions,
                    response_summary=_response_summary(response_text),
                ) from exc
            raise AxlCollectionError(f"HTTP {exc.code}: {_response_summary(response_text)}") from exc
        except urllib.error.URLError as exc:
            _write_api_artifact(
                context,
                context.publisher_ip,
                artifact_operation or operation,
                request_artifact,
                f"TRANSPORT ERROR\n{exc.reason}\n",
            )
            raise AxlCollectionError(str(exc.reason)) from exc
        except OSError as exc:
            _write_api_artifact(
                context,
                context.publisher_ip,
                artifact_operation or operation,
                request_artifact,
                f"OS ERROR\n{exc}\n",
            )
            raise AxlCollectionError(str(exc)) from exc

        _write_api_artifact(
            context,
            context.publisher_ip,
            artifact_operation or operation,
            request_artifact,
            response_artifact,
        )
        return response_text


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


def _soap_envelope(body: str, axl_version: str) -> str:
    axl_namespace = f"http://www.cisco.com/AXL/API/{axl_version}"
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAP_NAMESPACE}" xmlns:axl="{axl_namespace}">
  <soapenv:Body>
    {body}
  </soapenv:Body>
</soapenv:Envelope>
"""


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


def _format_http_request(endpoint: str, *, headers: dict[str, str], body: str) -> str:
    header_lines = "\n".join(f"{name}: {value}" for name, value in sorted(headers.items()))
    return f"POST {endpoint} HTTP/1.1\n{header_lines}\n\n{body}"


def _format_http_response(
    *,
    status: int | None,
    reason: str | None,
    headers: object,
    body: str,
) -> str:
    status_line = f"HTTP {status or 'unknown'}"
    if reason:
        status_line = f"{status_line} {reason}"
    header_lines = _format_response_headers(headers)
    if header_lines:
        return f"{status_line}\n{header_lines}\n\n{body}"
    return f"{status_line}\n\n{body}"


def _format_response_headers(headers: object) -> str:
    if headers is None:
        return ""
    if hasattr(headers, "items"):
        return "\n".join(f"{name}: {value}" for name, value in headers.items())
    return str(headers).strip()


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


def _version_sort_key(version: str) -> tuple[int, ...]:
    normalized = version.lower().replace(".x", ".0")
    return tuple(int(part) for part in normalized.split(".") if part.isdigit())


def _write_api_artifact(
    context: CollectionContext,
    node: str,
    operation: str,
    request: str,
    response: str,
) -> None:
    store = context.artifact_store
    if store is None:
        return
    store.write_api_exchange(
        node,
        "axl",
        operation,
        request=request,
        response=response,
    )
