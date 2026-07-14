"""Read-only Unity Connection UCOS CLI collection."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.collectors.ssh_preflight import (
    collect_preflighted_nodes,
    preflight_ssh_nodes,
)
from cisco_collab_health.models.facts import (
    AssessmentFacts,
    ClusterIdentity,
    CollaborationNode,
    ConfigurationObjectFact,
    PlatformCheckFact,
    ServiceStatusFact,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import SshCommandResult, SshCommandTimeout, UcosSshSession

@dataclass(frozen=True)
class UcosCommand:
    """Declarative metadata for a bounded, read-only UCOS command."""

    command_id: str
    command: str
    timeout_seconds: int
    diagnostic_only: bool = True
    output_sensitive: bool = True


@dataclass(frozen=True)
class CucInformixProbe:
    """One fixed, bounded, experimental CUC Informix SELECT probe."""

    probe_id: str
    database: str
    query: str
    object_type: str
    identity_field: str
    detail_fields: tuple[str, ...]
    row_limit: int = 100
    timeout_seconds: int = 30

    @property
    def command(self) -> str:
        return f"run cuc dbquery {self.database} {self.query}"


CUC_COMMAND_CATALOG = (
    UcosCommand("cuc.show_status", "show status", 30),
    UcosCommand("cuc.show_version_active", "show version active", 30),
    UcosCommand("cuc.show_version_inactive", "show version inactive", 30),
    UcosCommand("cuc.show_hardware", "show hardware", 30),
    UcosCommand("cuc.show_network_cluster", "show network cluster", 30),
    UcosCommand("cuc.show_network_eth0_detail", "show network eth0 detail", 30),
    UcosCommand("cuc.utils_diagnose_test", "utils diagnose test", 180),
    UcosCommand("cuc.utils_service_list", "utils service list", 120),
    UcosCommand("cuc.utils_core_active_list", "utils core active list", 120),
    UcosCommand("cuc.show_cluster_status", "show cuc cluster status", 30),
)
CUC_SAFE_CLI_COMMANDS = tuple(item.command for item in CUC_COMMAND_CATALOG)

CUC_INFORMIX_PROBE_CATALOG = (
    CucInformixProbe(
        "cuc.sql.duplicate_extensions",
        "unitydirdb",
        "select first 100 dtmfaccessid, count(dtmfaccessid) as occurrencecount "
        "from vw_user where dtmfaccessid is not null and dtmfaccessid != '' "
        "group by dtmfaccessid having count(dtmfaccessid) > 1 "
        "order by occurrencecount desc",
        "CucSqlDuplicateExtension",
        "dtmfaccessid",
        ("occurrencecount",),
    ),
    CucInformixProbe(
        "cuc.sql.alternate_contact_transfers",
        "unitydirdb",
        "select first 100 ch.displayname as callhandler, ch.dtmfaccessid, "
        "me.touchtonekey, acn.transfernumber from vw_callhandler as ch "
        "inner join vw_menuentry as me on ch.objectid=me.callhandlerobjectid "
        "and ch.isprimary='0' and me.action='7' "
        "inner join vw_alternatecontactnumber as acn "
        "on acn.menuentryobjectid=me.objectid",
        "CucSqlAlternateContactTransfer",
        "callhandler",
        ("dtmfaccessid", "touchtonekey", "transfernumber"),
    ),
    CucInformixProbe(
        "cuc.sql.system_transfer_targets",
        "unitydirdb",
        "select first 100 ch.displayname as callhandler, ch.dtmfaccessid, "
        "me.touchtonekey, me.targetconversation from vw_callhandler as ch "
        "inner join vw_menuentry as me on ch.objectid=me.callhandlerobjectid "
        "and ch.isprimary='0' where me.targetconversation in "
        "('SubSysTransfer','SystemTransfer','AD')",
        "CucSqlSystemTransferTarget",
        "callhandler",
        ("dtmfaccessid", "touchtonekey", "targetconversation"),
    ),
)

_FORBIDDEN_SQL = re.compile(
    r"(?i)\b(?:insert|update|delete|execute|drop|alter|create|truncate|merge|grant|revoke)\b"
)


class CliSession(Protocol):
    def __enter__(self) -> "CliSession": ...
    def __exit__(self, *_: object) -> None: ...
    def execute(
        self, command: str, *, timeout_seconds: int | None = None
    ) -> SshCommandResult: ...


class CucPlatformCollector:
    """Capture bounded, read-only UCOS health output over SSH."""

    name = "cuc_platform_cli"

    def __init__(
        self, session_factory: Callable[[CollectionContext], CliSession] | None = None
    ) -> None:
        self.session_factory = session_factory or UcosSshSession

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        notes = [
            "CUC Informix validation is experimental and uses only fixed, publisher-only "
            "SELECT FIRST 100 probes against unitydirdb."
        ]
        version: str | None = None
        publisher = context.publisher_ip or context.target
        if not publisher:
            return CollectionResult(self.name, facts, warnings=["CUC target is missing."])
        publisher_contexts, preflight_warnings = preflight_ssh_nodes(
            context, (publisher,), self.session_factory
        )
        warnings.extend(preflight_warnings)
        if not publisher_contexts:
            return CollectionResult(self.name, facts, warnings=warnings, notes=notes)
        cluster_output = self._collect_cluster_listing(context, publisher, facts, warnings)
        for cluster_node in _cuc_cluster_nodes(cluster_output, target_id=context.target_id):
            facts.add_node(cluster_node)
        nodes = tuple(dict.fromkeys(context.discovered_nodes or tuple(
            item.address or item.name for item in facts.nodes
        ) or (publisher,)))
        remaining_nodes = tuple(node for node in nodes if node and node != publisher)
        additional_contexts, additional_warnings = preflight_ssh_nodes(
            context, remaining_nodes, self.session_factory
        )
        warnings.extend(additional_warnings)
        ready_by_node = {publisher: publisher_contexts[0]}
        ready_by_node.update(
            {
                node: item
                for item in additional_contexts
                if (node := item.publisher_ip or item.target) is not None
            }
        )
        ready = [ready_by_node[node] for node in nodes if node in ready_by_node]
        for node, node_facts, node_warnings, node_version in collect_preflighted_nodes(
            ready, context.ssh_parallel_workers, self._collect_node_result
        ):
            facts.merge(node_facts)
            warnings.extend(node_warnings)
            if node == publisher and node_version:
                version = node_version
        if publisher in ready_by_node:
            self._collect_informix_probes(ready_by_node[publisher], publisher, facts, warnings)
        if version:
            facts.cluster = ClusterIdentity(publisher, "Cisco Unity Connection", version)
        return CollectionResult(self.name, facts, warnings=warnings, notes=notes)

    def _collect_node_result(
        self, context: CollectionContext
    ) -> tuple[str, AssessmentFacts, list[str], str | None]:
        facts = AssessmentFacts()
        warnings: list[str] = []
        node = context.publisher_ip or context.target or "unknown"
        version = self._collect_node(context, node, facts, warnings)
        return node, facts, warnings, version

    def _collect_cluster_listing(
        self, context: CollectionContext, node: str, facts: AssessmentFacts, warnings: list[str]
    ) -> str:
        """Discover CUC members before collecting platform evidence from each member."""

        definition = next(item for item in CUC_COMMAND_CATALOG if item.command == "show network cluster")
        try:
            with self.session_factory(context) as session:
                _progress(
                    context,
                    f"CUC CLI {node}: running '{definition.command}' (up to {definition.timeout_seconds}s)",
                )
                result = session.execute(definition.command, timeout_seconds=definition.timeout_seconds)
        except Exception as exc:
            warnings.append(f"CUC SSH session failed on {node}: {exc}")
            return ""
        if context.artifact_store is not None:
            context.artifact_store.write_command_output(node, definition.command, result.output)
        facts.platform_checks.append(_cuc_check(node, definition, "collected", result.output, result.paged))
        _progress(context, f"CUC CLI {node}: completed '{definition.command}'")
        return result.output

    def _collect_node(
        self, context: CollectionContext, node: str, facts: AssessmentFacts, warnings: list[str]
    ) -> str | None:
        version: str | None = None
        try:
            with self.session_factory(context) as session:
                for definition in CUC_COMMAND_CATALOG:
                    if definition.command == "show network cluster":
                        continue
                    _progress(
                        context,
                        f"CUC CLI {node}: running '{definition.command}' "
                        f"(up to {definition.timeout_seconds}s)",
                    )
                    try:
                        result = session.execute(definition.command, timeout_seconds=definition.timeout_seconds)
                    except SshCommandTimeout as exc:
                        if context.artifact_store is not None and exc.output:
                            context.artifact_store.write_command_output(node, definition.command, exc.output)
                        facts.platform_checks.append(_cuc_check(node, definition, "incomplete", exc.output, exc.paged, incomplete=True))
                        warnings.append(f"CUC CLI '{definition.command}' on {node} did not return to the prompt; retained {len(exc.output)} characters of partial output.")
                        _progress(context, f"CUC CLI {node}: partial output retained for '{definition.command}'")
                        continue
                    except Exception as exc:
                        warnings.append(f"CUC CLI '{definition.command}' on {node} failed: {exc}")
                        continue
                    if context.artifact_store is not None:
                        context.artifact_store.write_command_output(node, definition.command, result.output)
                    if definition.command == "show version active":
                        version = _cuc_version(result.output)
                    if definition.command == "utils service list":
                        facts.services.extend(_cuc_service_status(node, result.output))
                    facts.platform_checks.append(_cuc_check(node, definition, "collected", result.output, result.paged))
                    _progress(context, f"CUC CLI {node}: completed '{definition.command}'")
        except Exception as exc:
            warnings.append(f"CUC SSH session failed on {node}: {exc}")
        return version

    def _collect_informix_probes(
        self, context: CollectionContext, node: str, facts: AssessmentFacts,
        warnings: list[str],
    ) -> None:
        """Run fixed experimental SELECT probes on the CUC publisher only."""

        try:
            with self.session_factory(context) as session:
                for probe in CUC_INFORMIX_PROBE_CATALOG:
                    try:
                        _progress(
                            context,
                            f"CUC Informix {node}: running '{probe.probe_id}' "
                            f"(up to {probe.timeout_seconds}s)",
                        )
                        _validate_cuc_informix_probe(probe)
                        result = session.execute(
                            probe.command, timeout_seconds=probe.timeout_seconds,
                        )
                    except SshCommandTimeout as exc:
                        if context.artifact_store is not None and exc.output:
                            context.artifact_store.write_command_output(
                                node, probe.probe_id,
                                f"SQL command: {probe.command}\n\n{exc.output}",
                            )
                        facts.platform_checks.append(
                            _cuc_informix_check(node, probe, "incomplete", exc.output)
                        )
                        warnings.append(
                            f"Experimental CUC Informix probe '{probe.probe_id}' timed out; "
                            "partial output was retained privately."
                        )
                        continue
                    except Exception as exc:
                        warnings.append(
                            f"Experimental CUC Informix probe '{probe.probe_id}' failed: {exc}"
                        )
                        continue
                    if context.artifact_store is not None:
                        context.artifact_store.write_command_output(
                            node, probe.probe_id,
                            f"SQL command: {probe.command}\n\n{result.output}",
                        )
                    rows = _parse_cuc_dbquery_rows(result.output)
                    if _cuc_dbquery_error(result.output):
                        status = "unsupported"
                    elif rows or _cuc_dbquery_zero_rows(result.output):
                        status = "collected"
                    else:
                        status = "unparsed"
                    facts.platform_checks.append(
                        _cuc_informix_check(node, probe, status, result.output, rows=rows)
                    )
                    if status == "unsupported":
                        warnings.append(
                            f"Experimental CUC Informix probe '{probe.probe_id}' returned a "
                            "database/schema error; see private evidence."
                        )
                        continue
                    if status == "unparsed":
                        warnings.append(
                            f"Experimental CUC Informix probe '{probe.probe_id}' returned an "
                            "unrecognized result shape; see private evidence."
                        )
                        continue
                    facts.configuration_objects.extend(
                        _cuc_informix_facts(probe, rows)
                    )
                    _progress(context, f"CUC Informix {node}: completed '{probe.probe_id}'")
        except Exception as exc:
            warnings.append(f"CUC Informix validation session failed on {node}: {exc}")


def _progress(context: CollectionContext, message: str) -> None:
    if context.progress is not None:
        context.progress(message)


def _cuc_check(
    node: str, definition: UcosCommand, status: str, output: str, paged: bool,
    *, incomplete: bool = False,
) -> PlatformCheckFact:
    return PlatformCheckFact(
        node=node, check_name=definition.command, status=status,
        details={
            "output_captured": str(bool(output)).lower(), "output_length": str(len(output)),
            "paged": str(paged).lower(), "completion": "prompt timeout" if incomplete else "complete",
            "command_id": definition.command_id, "timeout_seconds": str(definition.timeout_seconds),
            "diagnostic_only": str(definition.diagnostic_only).lower(),
            **_cuc_cli_summary(definition.command, output),
        }, source="CUC.UCOS.CLI",
    )


def _validate_cuc_informix_probe(probe: CucInformixProbe) -> None:
    """Reject any catalog entry that is not one fixed, bounded SELECT."""

    query = probe.query.strip()
    if probe.database != "unitydirdb":
        raise ValueError("experimental probes are restricted to unitydirdb")
    if not re.match(r"(?is)^select\s+first\s+\d+\s+", query):
        raise ValueError("CUC Informix probes must begin with SELECT FIRST")
    limit = re.match(r"(?is)^select\s+first\s+(\d+)\s+", query)
    if limit is None or int(limit.group(1)) != probe.row_limit or probe.row_limit > 100:
        raise ValueError("CUC Informix query limit must match a maximum of 100 rows")
    if ";" in query or "--" in query or "/*" in query or "*/" in query:
        raise ValueError("CUC Informix probes cannot contain statement separators or comments")
    if _FORBIDDEN_SQL.search(query):
        raise ValueError("CUC Informix probe contains a non-read-only SQL keyword")


def _parse_cuc_dbquery_rows(output: str) -> list[dict[str, str]]:
    """Parse the fixed-width table emitted by ``run cuc dbquery``."""

    lines = output.splitlines()
    for index, line in enumerate(lines):
        spans = [(match.start(), match.end()) for match in re.finditer(r"-+", line)]
        if not spans or re.sub(r"[-\s]", "", line):
            continue
        header_index = index - 1
        while header_index >= 0 and not lines[header_index].strip():
            header_index -= 1
        if header_index < 0:
            return []
        header = lines[header_index]
        names = [header[start:end].strip().lower() for start, end in spans]
        if not all(names):
            return []
        rows: list[dict[str, str]] = []
        for row_line in lines[index + 1:]:
            stripped = row_line.strip()
            if not stripped:
                if rows:
                    break
                continue
            if re.match(r"(?i)^(?:rows?:|no records found|command failed)", stripped):
                break
            row = {
                name: row_line[start:end].strip()
                for name, (start, end) in zip(names, spans, strict=True)
            }
            if any(row.values()):
                rows.append(row)
        return rows
    return []


def _cuc_dbquery_error(output: str) -> bool:
    return bool(re.search(
        r"(?im)^(?:command failed|.*sql error|.*syntax error|.*(?:table|column).*"
        r"(?:not found|does not exist))",
        output,
    ))


def _cuc_dbquery_zero_rows(output: str) -> bool:
    return bool(re.search(r"(?im)^(?:no records found|rows?:\s*0)\s*$", output))


def _cuc_informix_check(
    node: str, probe: CucInformixProbe, status: str, output: str,
    *, rows: list[dict[str, str]] | None = None,
) -> PlatformCheckFact:
    return PlatformCheckFact(
        node=node,
        check_name=probe.probe_id,
        status=status,
        details={
            "experimental": "true",
            "database": probe.database,
            "row_limit": str(probe.row_limit),
            "rows_normalized": str(len(rows or [])),
            "output_captured": str(bool(output)).lower(),
            "output_length": str(len(output)),
            "timeout_seconds": str(probe.timeout_seconds),
            "read_only_validated": "true",
        },
        source="CUC.INFORMIX.SQL",
    )


def _cuc_informix_facts(
    probe: CucInformixProbe, rows: list[dict[str, str]],
) -> list[ConfigurationObjectFact]:
    facts = []
    for row in rows:
        identity = row.get(probe.identity_field, "").strip()
        if not identity:
            continue
        facts.append(ConfigurationObjectFact(
            object_type=probe.object_type,
            name=identity,
            details={
                "experimental": "true",
                "probe_id": probe.probe_id,
                **{
                    field: value
                    for field in probe.detail_fields
                    if (value := row.get(field, "").strip())
                },
            },
            source="CUC.INFORMIX.SQL",
        ))
    return facts


def _cuc_cli_summary(command: str, output: str) -> dict[str, str]:
    """Extract conservative health summaries while retaining the full CLI artifact."""

    if command == "utils diagnose test":
        return {
            "passed": str(len(re.findall(r"(?im)^test\s+-.*:\s*Passed", output))),
            "failed": str(len(re.findall(r"(?im)^test\s+-.*:\s*Failed", output))),
            "skipped": str(len(re.findall(r"(?im)^skip\s+-", output))),
        }
    if command == "utils service list":
        return {
            "started": str(len(re.findall(r"\[STARTED\]", output))),
            "stopped": str(len(re.findall(r"\[STOPPED\]", output))),
            "not_activated": str(output.count("Service Not Activated")),
        }
    if command == "show cuc cluster status":
        return {
            "primary_nodes": str(len(re.findall(r"\bPrimary\b", output))),
            "secondary_nodes": str(len(re.findall(r"\bSecondary\b", output))),
            "connected_peers": str(len(re.findall(r"\bConnected\b", output))),
            "unhealthy_states": str(len(re.findall(r"(?im)\b(?:failed|error|inactive)\b", output))),
        }
    if command == "utils core active list":
        return {"core_files": "0" if "No core files found" in output else "present"}
    if command == "show network eth0 detail":
        status = re.search(r"Status\s*:\s*(\w+)", output)
        duplicate = re.search(r"Duplicate IP\s*:\s*(\w+)", output)
        return {
            "link_status": status.group(1).lower() if status else "unknown",
            "duplicate_ip": duplicate.group(1).lower() if duplicate else "unknown",
        }
    if command == "show status":
        disk_usage = [
            int(match.group(1))
            for match in re.finditer(r"(?m)^Disk/\S+.*?\((\d+)%\)", output)
        ]
        uptime = re.search(r"\bup\s+(\d+)\s+days?", output, re.IGNORECASE)
        uptime_days = int(uptime.group(1)) if uptime else None
        return {
            "max_disk_usage_percent": str(max(disk_usage)) if disk_usage else "unknown",
            "disk_warning_count": str(sum(value >= 90 for value in disk_usage)),
            "disk_critical_count": str(sum(value >= 95 for value in disk_usage)),
            "uptime_days": str(uptime_days) if uptime_days is not None else "unknown",
        }
    return {}


def _cuc_service_status(node: str, output: str) -> list[ServiceStatusFact]:
    """Normalize UCOS service-list entries without treating inactive services as failures."""

    services: list[ServiceStatusFact] = []
    pattern = re.compile(r"(?m)^(?P<name>.+?)\[(?P<state>STARTED|STOPPED)\](?P<detail>.*)$")
    for match in pattern.finditer(output):
        detail = match.group("detail").strip()
        services.append(
            ServiceStatusFact(
                node=node,
                service_name=match.group("name").strip(),
                activated="service not activated" not in detail.lower(),
                status=match.group("state").title(),
                uptime_seconds=None,
                source="CUC.UCOS.CLI",
                reason=detail or None,
            )
        )
    return services


def _cuc_version(output: str) -> str | None:
    match = re.search(r"(?im)^Active Master Version:\s*(\S+)", output)
    return match.group(1) if match else None


def _cuc_cluster_nodes(output: str, *, target_id: str | None) -> list[CollaborationNode]:
    """Normalize the bounded UCOS cluster listing into shared report node facts."""

    nodes: list[CollaborationNode] = []
    pattern = re.compile(
        r"(?im)^(?P<address>\S+)\s+(?P<name>\S+)\s+\S+\s+"
        r"(?P<role>Publisher|Subscriber)\b"
    )
    for match in pattern.finditer(output):
        nodes.append(
            CollaborationNode(
                name=match.group("name"),
                address=match.group("address"),
                role=match.group("role").lower(),
                technology="cuc",
                target_id=target_id,
            )
        )
    return nodes
