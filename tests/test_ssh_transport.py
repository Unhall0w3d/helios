"""Tests for the prompt-aware UCOS SSH transport."""

from __future__ import annotations

import unittest

from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import UcosSshSession


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
