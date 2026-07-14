"""Prompt-aware SSH transport for Cisco UCOS appliance CLI sessions."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import monotonic, sleep
from typing import Any

from cisco_collab_health.models.runtime import CollectionContext

UCOS_PROMPT = re.compile(r"(?m)^admin:\s*$")
PAGER_MARKERS = ("--More--", "<--- More --->", "Press any key")


@dataclass(frozen=True)
class SshCommandResult:
    """Raw terminal output from one completed UCOS command."""

    command: str
    output: str
    paged: bool = False
    completed: bool = True


class SshCommandTimeout(TimeoutError):
    """A command exceeded its budget after producing terminal output."""

    def __init__(self, output: str, paged: bool) -> None:
        super().__init__("Timed out waiting for the UCOS admin prompt")
        self.output = output
        self.paged = paged


def ssh_host_key_fingerprint(key: Any) -> str:
    """Return the OpenSSH-style SHA-256 fingerprint for a server key."""

    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class HostKeyApprovalPolicy:
    """Paramiko missing-key policy that asks an interactive operator to approve a key."""

    def __init__(self, approval: Callable[[str, str, str], bool]) -> None:
        self.approval = approval
        self.approved = False

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        algorithm = key.get_name()
        fingerprint = ssh_host_key_fingerprint(key)
        if not self.approval(hostname, algorithm, fingerprint):
            raise RuntimeError(f"SSH host key for {hostname} was not approved")
        client.get_host_keys().add(hostname, algorithm, key)
        self.approved = True


class UcosSshSession:
    """One PTY-backed, prompt-driven SSH session for UCOS commands."""

    def __init__(
        self,
        context: CollectionContext,
        *,
        client_factory: Callable[[], Any] | None = None,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self.context = context
        self.client_factory = client_factory
        self.sleeper = sleeper
        self.client: Any | None = None
        self.channel: Any | None = None
        self._host_key_policy: HostKeyApprovalPolicy | None = None

    def __enter__(self) -> "UcosSshSession":
        host = self.context.publisher_ip or self.context.target
        if not host or not self.context.os_username or self.context.os_password is None:
            raise RuntimeError("Platform SSH host or credentials are unavailable")
        if self.client_factory is None:
            try:
                import paramiko  # type: ignore[import-untyped]
            except ImportError as exc:
                raise RuntimeError("paramiko is required for SSH collection") from exc
            self.client = paramiko.SSHClient()
            self.client.load_system_host_keys()
            known_hosts = Path.home() / ".ssh" / "known_hosts"
            if known_hosts.exists():
                self.client.load_host_keys(str(known_hosts))
            if self.context.host_key_approval is not None:
                known_hosts.parent.mkdir(parents=True, exist_ok=True)
                self._host_key_policy = HostKeyApprovalPolicy(self.context.host_key_approval)
                self.client.set_missing_host_key_policy(self._host_key_policy)
            elif self.context.accept_new_host_key:
                known_hosts.parent.mkdir(parents=True, exist_ok=True)
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            else:
                self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            self.client = self.client_factory()
        self.client.connect(
            hostname=host,
            username=self.context.os_username,
            password=self.context.os_password,
            timeout=self.context.timeout_seconds,
            banner_timeout=self.context.timeout_seconds,
            auth_timeout=self.context.timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        if self.client_factory is None and (
            self.context.accept_new_host_key
            or (self._host_key_policy is not None and self._host_key_policy.approved)
        ):
            self.client.save_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
        transport = self.client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport was not established")
        self.channel = transport.open_session()
        self.channel.get_pty(term="vt100", width=200, height=1000)
        self.channel.invoke_shell()
        self._read_until_prompt()
        return self

    def __exit__(self, *_: object) -> None:
        if self.channel is not None:
            self.channel.close()
        if self.client is not None:
            self.client.close()

    def execute(self, command: str, *, timeout_seconds: int | None = None) -> SshCommandResult:
        if self.channel is None:
            raise RuntimeError("SSH shell session is not open")
        self.channel.send(command + "\n")
        output, paged = self._read_until_prompt(timeout_seconds=timeout_seconds)
        return SshCommandResult(command=command, output=_strip_echo(output, command), paged=paged)

    def _read_until_prompt(self, *, timeout_seconds: int | None = None) -> tuple[str, bool]:
        if self.channel is None:
            raise RuntimeError("SSH shell session is not open")
        chunks: list[str] = []
        paged = False
        deadline = monotonic() + (timeout_seconds or self.context.timeout_seconds)
        while monotonic() < deadline:
            if self.channel.recv_ready():
                text = self.channel.recv(65535).decode("utf-8", errors="replace")
                chunks.append(text)
                current = "".join(chunks)
                if any(marker in current for marker in PAGER_MARKERS):
                    self.channel.send(" ")
                    paged = True
                    chunks[-1] = text.replace("--More--", "").replace("<--- More --->", "")
                    continue
                if UCOS_PROMPT.search(current.rstrip("\r\n")):
                    return current, paged
            else:
                self.sleeper(0.05)
        raise SshCommandTimeout("".join(chunks), paged)


def _strip_echo(output: str, command: str) -> str:
    """Remove a single echoed command while retaining exact terminal evidence."""

    lines = output.replace("\r\n", "\n").split("\n")
    if lines and lines[0].strip() == command:
        lines.pop(0)
    if lines and UCOS_PROMPT.fullmatch(lines[-1].strip()):
        lines.pop()
    return "\n".join(lines).strip()
