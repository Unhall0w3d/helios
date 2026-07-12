"""Read-only Unity Connection UCOS CLI collection."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, PlatformCheckFact
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


CUC_COMMAND_CATALOG = (
    UcosCommand("cuc.show_status", "show status", 30),
    UcosCommand("cuc.show_version_active", "show version active", 30),
    UcosCommand("cuc.show_version_inactive", "show version inactive", 30),
    UcosCommand("cuc.show_hardware", "show hardware", 30),
    UcosCommand("cuc.show_network_cluster", "show network cluster", 30),
    UcosCommand("cuc.show_network_eth0_detail", "show network eth0 detail", 30),
    UcosCommand("cuc.show_perf_processor_memory", "show perf query class Processor|Memory", 30),
    UcosCommand("cuc.utils_diagnose_test", "utils diagnose test", 180),
    UcosCommand("cuc.utils_service_list", "utils service list", 120),
    UcosCommand("cuc.utils_core_active_list", "utils core active list", 120),
    UcosCommand("cuc.show_cluster_status", "show cuc cluster status", 30),
)
CUC_SAFE_CLI_COMMANDS = tuple(item.command for item in CUC_COMMAND_CATALOG)


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
        node = context.publisher_ip or context.target
        if not node:
            return CollectionResult(self.name, facts, warnings=["CUC target is missing."])
        try:
            with self.session_factory(context) as session:
                for definition in CUC_COMMAND_CATALOG:
                    command = definition.command
                    try:
                        result = session.execute(command, timeout_seconds=definition.timeout_seconds)
                    except SshCommandTimeout as exc:
                        partial_output = exc.output
                        if context.artifact_store is not None and partial_output:
                            context.artifact_store.write_command_output(node, command, partial_output)
                        facts.platform_checks.append(
                            PlatformCheckFact(
                                node=node,
                                check_name=command,
                                status="incomplete",
                                details={
                                    "output_captured": str(bool(partial_output)).lower(),
                                    "output_length": str(len(partial_output)),
                                    "paged": str(exc.paged).lower(),
                                    "completion": "prompt timeout",
                                    "timeout_seconds": str(
                                        definition.timeout_seconds
                                    ),
                                },
                                source="CUC.UCOS.CLI",
                            )
                        )
                        warnings.append(
                            f"CUC CLI '{command}' did not return to the prompt; "
                            f"retained {len(partial_output)} characters of partial output."
                        )
                        continue
                    except Exception as exc:
                        warnings.append(f"CUC CLI '{command}' failed: {exc}")
                        continue
                    if context.artifact_store is not None:
                        context.artifact_store.write_command_output(node, command, result.output)
                    facts.platform_checks.append(
                        PlatformCheckFact(
                            node=node,
                            check_name=command,
                            status="collected",
                            details={
                                "output_captured": "true",
                                "output_length": str(len(result.output)),
                                "paged": str(result.paged).lower(),
                                "command_id": definition.command_id,
                                "timeout_seconds": str(definition.timeout_seconds),
                                "diagnostic_only": str(definition.diagnostic_only).lower(),
                                **_cuc_cli_summary(command, result.output),
                            },
                            source="CUC.UCOS.CLI",
                        )
                    )
        except Exception as exc:
            warnings.append(f"CUC SSH session failed: {exc}")
        return CollectionResult(self.name, facts, warnings=warnings)


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
    return {}
