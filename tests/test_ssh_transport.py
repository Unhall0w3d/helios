"""Tests for the prompt-aware UCOS SSH transport."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import (
    HostKeyApprovalPolicy,
    UcosSshSession,
    ssh_host_key_fingerprint,
)


class FakeChannel:
    def __init__(self) -> None:
        self.responses = [b"Welcome\r\nadmin:"]
        self.sent: list[str] = []

    def get_pty(self, **_kwargs: object) -> None:
        return None

    def invoke_shell(self) -> None:
        return None

    def send(self, data: str) -> None:
        self.sent.append(data)
        if data.endswith("\n"):
            command = data.strip()
            self.responses.append(f"{command}\r\nresult\r\nadmin:".encode())

    def recv_ready(self) -> bool:
        return bool(self.responses)

    def recv(self, _size: int) -> bytes:
        return self.responses.pop(0)

    def close(self) -> None:
        return None


class FakeTransport:
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel

    def open_session(self) -> FakeChannel:
        return self.channel


class FakeClient:
    def __init__(self) -> None:
        self.channel = FakeChannel()
        self.connected = False

    def connect(self, **_kwargs: object) -> None:
        self.connected = True

    def get_transport(self) -> FakeTransport:
        return FakeTransport(self.channel)

    def close(self) -> None:
        return None


class FakeHostKey:
    def asbytes(self) -> bytes:
        return b"server-public-key"

    def get_name(self) -> str:
        return "ssh-ed25519"


class FakeHostKeys:
    def __init__(self) -> None:
        self.added: list[tuple[str, str, FakeHostKey]] = []

    def add(self, hostname: str, algorithm: str, key: FakeHostKey) -> None:
        self.added.append((hostname, algorithm, key))


class FakePolicyClient:
    def __init__(self) -> None:
        self.host_keys = FakeHostKeys()

    def get_host_keys(self) -> FakeHostKeys:
        return self.host_keys


class UcosSshSessionTests(unittest.TestCase):
    def test_pty_shell_reads_to_prompt_and_strips_echo(self) -> None:
        client = FakeClient()
        context = CollectionContext(
            publisher_ip="192.0.2.20", os_username="admin", os_password="secret"
        )
        with UcosSshSession(
            context, client_factory=lambda: client, sleeper=lambda _: None
        ) as session:
            result = session.execute("show status")

        self.assertTrue(client.connected)
        self.assertEqual(result.output, "result")
        self.assertIn("show status\n", client.channel.sent)

    def test_host_key_approval_records_fingerprint_and_saves_approved_key(self) -> None:
        client = FakePolicyClient()
        key = FakeHostKey()
        requested: list[tuple[str, str, str]] = []
        policy = HostKeyApprovalPolicy(
            lambda host, algorithm, fingerprint: requested.append((host, algorithm, fingerprint))
            or True
        )

        policy.missing_host_key(client, "192.0.2.20", key)

        self.assertEqual(
            requested,
            [("192.0.2.20", "ssh-ed25519", ssh_host_key_fingerprint(key))],
        )
        self.assertTrue(policy.approved)
        self.assertEqual(client.host_keys.added, [("192.0.2.20", "ssh-ed25519", key)])

    def test_host_key_approval_rejects_unapproved_key(self) -> None:
        policy = HostKeyApprovalPolicy(lambda *_: False)

        with self.assertRaisesRegex(RuntimeError, "not approved"):
            policy.missing_host_key(FakePolicyClient(), "192.0.2.20", FakeHostKey())
        self.assertFalse(policy.approved)
