"""Read-only Unity Connection UCOS CLI collection."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from cisco_collab_health.collectors.base import CollectionResult
from cisco_collab_health.models.facts import AssessmentFacts, PlatformCheckFact
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import SshCommandResult, UcosSshSession

CUC_SAFE_CLI_COMMANDS = (
    "show status",
    "show version",
    "show network",
    "show memory",
    "show hardware",
    "utils service list",
)


class CliSession(Protocol):
    def __enter__(self) -> "CliSession": ...
    def __exit__(self, *_: object) -> None: ...
    def execute(self, command: str) -> SshCommandResult: ...


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
                        result = session.execute(command)
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
