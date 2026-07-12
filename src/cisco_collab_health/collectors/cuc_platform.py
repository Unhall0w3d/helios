"""Read-only Unity Connection UCOS CLI collection."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, PlatformCheckFact
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import SshCommandResult, SshCommandTimeout, UcosSshSession

CUC_SAFE_CLI_COMMANDS = (
    "show status",
    "show version active",
    "show version inactive",
    "show hardware",
    "show network cluster",
    "show network eth0 detail",
    "show perf query class Processor|Memory",
    "utils diagnose test",
    "utils service list",
    "utils core active list",
    "show cuc cluster status",
)

CUC_LONG_RUNNING_CLI_TIMEOUTS = {
    "utils diagnose test": 180,
    "utils service list": 120,
    "utils core active list": 120,
}


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
                for command in CUC_SAFE_CLI_COMMANDS:
                    try:
                        timeout_seconds = CUC_LONG_RUNNING_CLI_TIMEOUTS.get(command)
                        result = session.execute(command, timeout_seconds=timeout_seconds)
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
                                        CUC_LONG_RUNNING_CLI_TIMEOUTS.get(
                                            command, context.timeout_seconds
                                        )
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
                            },
                            source="CUC.UCOS.CLI",
                        )
                    )
        except Exception as exc:
            warnings.append(f"CUC SSH session failed: {exc}")
        return CollectionResult(self.name, facts, warnings=warnings)
