"""Tests for bounded Unity Connection UCOS CLI collection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.collectors.cuc_platform import (
    CUC_SAFE_CLI_COMMANDS,
    CucPlatformCollector,
)
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import SshCommandResult


class FakeSession:
    def __init__(self, context: CollectionContext, commands: list[str]) -> None:
        del context
        self.commands = commands

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, command: str) -> SshCommandResult:
        self.commands.append(command)
        return SshCommandResult(command, f"output for {command}")


class CucPlatformCollectorTests(unittest.TestCase):
    def test_collector_records_only_safe_commands_and_artifacts(self) -> None:
        commands: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            artifacts = ArtifactStore.create(Path(tmpdir), "cuc", None)
            result = CucPlatformCollector(
                session_factory=lambda context: FakeSession(context, commands)
            ).collect(CollectionContext(publisher_ip="192.0.2.20", artifact_store=artifacts))

            self.assertEqual(commands, list(CUC_SAFE_CLI_COMMANDS))
            self.assertEqual(len(result.facts.platform_checks), len(CUC_SAFE_CLI_COMMANDS))
            self.assertEqual(len(list(artifacts.root.rglob("*.txt"))), len(CUC_SAFE_CLI_COMMANDS))
