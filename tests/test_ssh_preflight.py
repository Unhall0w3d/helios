"""Tests for serial SSH enrollment preflight and bounded node workers."""

from __future__ import annotations

import threading
import time
import unittest

from cisco_collab_health.collectors.ssh_preflight import (
    collect_preflighted_nodes,
    preflight_ssh_nodes,
)
from cisco_collab_health.models.runtime import CollectionContext


class FakeSession:
    def __init__(self, node: str, entered: list[str], fail: bool = False) -> None:
        self.node = node
        self.entered = entered
        self.fail = fail

    def __enter__(self) -> "FakeSession":
        self.entered.append(self.node)
        if self.fail:
            raise RuntimeError("host key was not approved")
        return self

    def __exit__(self, *_: object) -> None:
        return None


class AuthenticationException(RuntimeError):
    pass


class SshPreflightTests(unittest.TestCase):
    def test_preflight_is_serial_and_excludes_failed_nodes(self) -> None:
        entered: list[str] = []

        def factory(context: CollectionContext) -> FakeSession:
            node = context.publisher_ip or "unknown"
            return FakeSession(node, entered, fail=node == "192.0.2.11")

        ready, warnings = preflight_ssh_nodes(
            CollectionContext(host_key_approval=lambda *_: True),
            ("192.0.2.10", "192.0.2.11", "192.0.2.10"),
            factory,
        )

        self.assertEqual(entered, ["192.0.2.10", "192.0.2.11"])
        self.assertEqual([context.publisher_ip for context in ready], ["192.0.2.10"])
        self.assertIsNone(ready[0].host_key_approval)
        self.assertEqual(len(warnings), 1)
        self.assertIn("192.0.2.11", warnings[0])

    def test_preflight_retries_only_authentication_failure_with_node_password(self) -> None:
        attempted_passwords: list[str | None] = []
        requested: list[tuple[str, str]] = []

        class PasswordSession:
            def __init__(self, context: CollectionContext) -> None:
                self.context = context

            def __enter__(self) -> "PasswordSession":
                attempted_passwords.append(self.context.os_password)
                if self.context.os_password != "subscriber-password":
                    raise AuthenticationException("Authentication failed.")
                return self

            def __exit__(self, *_: object) -> None:
                return None

        def retry(node: str, error: str) -> str:
            requested.append((node, error))
            return "subscriber-password"

        ready, warnings = preflight_ssh_nodes(
            CollectionContext(os_password="publisher-password", ssh_password_retry=retry),
            ("192.0.2.11",),
            PasswordSession,
        )

        self.assertEqual(attempted_passwords, ["publisher-password", "subscriber-password"])
        self.assertEqual(requested, [("192.0.2.11", "Authentication failed.")])
        self.assertFalse(warnings)
        self.assertEqual(ready[0].os_password, "subscriber-password")
        self.assertIsNone(ready[0].ssh_password_retry)
        self.assertEqual(
            ready[0].node_platform_passwords,
            {"192.0.2.11": "subscriber-password"},
        )

    def test_collection_is_bounded_and_preserves_node_order(self) -> None:
        contexts = [CollectionContext(publisher_ip=f"192.0.2.{item}") for item in range(10, 13)]
        lock = threading.Lock()
        running = 0
        maximum = 0

        def collect_one(context: CollectionContext) -> str:
            nonlocal running, maximum
            with lock:
                running += 1
                maximum = max(maximum, running)
            time.sleep(0.02)
            with lock:
                running -= 1
            return context.publisher_ip or ""

        results = collect_preflighted_nodes(contexts, 2, collect_one)

        self.assertEqual(results, ["192.0.2.10", "192.0.2.11", "192.0.2.12"])
        self.assertEqual(maximum, 2)
