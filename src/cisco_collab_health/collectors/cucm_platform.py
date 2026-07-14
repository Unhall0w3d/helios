"""Read-only CUCM UCOS CLI diagnostic collection across discovered cluster nodes."""

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
from cisco_collab_health.models.facts import AssessmentFacts, PlatformCheckFact
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import SshCommandResult, SshCommandTimeout, UcosSshSession


@dataclass(frozen=True)
class UcosCommand:
    command_id: str
    command: str
    timeout_seconds: int


CUCM_COMMAND_CATALOG = (
    UcosCommand("cucm.show_status", "show status", 30),
    UcosCommand("cucm.show_version_active", "show version active", 30),
    UcosCommand("cucm.show_version_inactive", "show version inactive", 30),
    UcosCommand("cucm.utils_ntp_status", "utils ntp status", 45),
    UcosCommand("cucm.utils_drs_history", "utils disaster_recovery history backup", 60),
    UcosCommand("cucm.utils_drs_status", "utils disaster_recovery status backup", 60),
    UcosCommand("cucm.utils_dbreplication", "utils dbreplication runtimestate", 180),
    UcosCommand("cucm.utils_core_active", "utils core active list", 120),
    UcosCommand("cucm.utils_service_list", "utils service list", 120),
)


class CliSession(Protocol):
    def __enter__(self) -> "CliSession": ...
    def __exit__(self, *_: object) -> None: ...
    def execute(self, command: str, *, timeout_seconds: int | None = None) -> SshCommandResult: ...


class CucmPlatformCollector:
    """Collect bounded, read-only CUCM platform evidence after AXL node discovery."""

    name = "cucm_platform_cli"

    def __init__(self, session_factory: Callable[[CollectionContext], CliSession] | None = None) -> None:
        self.session_factory = session_factory or UcosSshSession

    def collect(self, context: CollectionContext) -> CollectionResult:
        facts = AssessmentFacts()
        warnings: list[str] = []
        nodes = tuple(dict.fromkeys(context.discovered_nodes or (context.publisher_ip or context.target,)))
        ready, preflight_warnings = preflight_ssh_nodes(
            context, (node for node in nodes if node), self.session_factory
        )
        warnings.extend(preflight_warnings)
        for node_facts, node_warnings in collect_preflighted_nodes(
            ready, context.ssh_parallel_workers, self._collect_node
        ):
            facts.merge(node_facts)
            warnings.extend(node_warnings)
        return CollectionResult(self.name, facts, warnings=warnings)

    def _collect_node(self, context: CollectionContext) -> tuple[AssessmentFacts, list[str]]:
        """Collect one trusted node; commands remain serial within its shell session."""

        facts = AssessmentFacts()
        warnings: list[str] = []
        node = context.publisher_ip or context.target or "unknown"
        try:
            with self.session_factory(context) as session:
                for definition in CUCM_COMMAND_CATALOG:
                    _progress(
                        context,
                        f"CUCM CLI {node}: running '{definition.command}' "
                        f"(up to {definition.timeout_seconds}s)",
                    )
                    try:
                        result = session.execute(definition.command, timeout_seconds=definition.timeout_seconds)
                    except SshCommandTimeout as exc:
                        if context.artifact_store is not None and exc.output:
                            context.artifact_store.write_command_output(node, definition.command, exc.output)
                        warnings.append(f"CUCM CLI '{definition.command}' on {node} did not return to the prompt.")
                        facts.platform_checks.append(_check(node, definition, "incomplete", exc.output, incomplete=True))
                        _progress(context, f"CUCM CLI {node}: partial output retained for '{definition.command}'")
                        continue
                    except Exception as exc:
                        warnings.append(f"CUCM CLI '{definition.command}' on {node} failed: {exc}")
                        continue
                    if context.artifact_store is not None:
                        context.artifact_store.write_command_output(node, definition.command, result.output)
                    facts.platform_checks.append(_check(node, definition, "collected", result.output))
                    _progress(context, f"CUCM CLI {node}: completed '{definition.command}'")
        except Exception as exc:
            warnings.append(f"CUCM SSH session failed on {node}: {exc}")
        return facts, warnings


def _progress(context: CollectionContext, message: str) -> None:
    if context.progress is not None:
        context.progress(message)


def _check(node: str, definition: UcosCommand, status: str, output: str, *, incomplete: bool = False) -> PlatformCheckFact:
    return PlatformCheckFact(
        node=node,
        check_name=definition.command,
        status=status,
        details={
            "command_id": definition.command_id,
            "timeout_seconds": str(definition.timeout_seconds),
            "output_length": str(len(output)),
            "completion": "prompt timeout" if incomplete else "complete",
            **_summary(definition.command, output),
        },
        source="CUCM.UCOS.CLI",
    )


def _summary(command: str, output: str) -> dict[str, str]:
    if command == "utils ntp status":
        match = re.search(r"synchroni[sz]ed to NTP server \(([^)]+)\) at stratum (\d+)", output, re.I)
        return {"synchronized": str(bool(match)).lower(), "server": match.group(1) if match else "unknown", "stratum": match.group(2) if match else "unknown", "bad_sources": str(len(re.findall(r"(?m)^\^(?:\?|x|-)", output)))}
    if command.startswith("utils disaster_recovery"):
        successes = re.findall(r"\bSUCCESS\b", output, re.I)
        unavailable = bool(re.search(r"master agent.*(?:down|processing)|network request timed out|error occurred", output, re.I))
        return {"successful_backup_entries": str(len(successes)), "drs_unavailable": str(unavailable).lower()}
    if command == "utils dbreplication runtimestate":
        rows = re.findall(r"(?m)^\S+\s+\d{1,3}(?:\.\d{1,3}){3}.*$", output)
        bad = [
            row for row in rows if not re.search(r"\([^)]+\)\s+Setup Completed\b", row, re.I)
        ]
        return {"replication_rows": str(len(rows)), "replication_bad_rows": str(len(bad))}
    if command == "utils core active list":
        return {"core_files": "0" if "No core files found" in output else "present"}
    if command == "show status":
        usage = [int(value) for value in re.findall(r"(?m)^Disk/\S+.*?\((\d+)%\)", output)]
        return {"max_disk_usage_percent": str(max(usage)) if usage else "unknown"}
    return {}
