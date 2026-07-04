"""TLS policy helpers shared by collectors and interface probes."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TlsPolicy:
    """TLS verification behavior for HTTPS probes and collectors."""

    verify: bool = False
    ca_bundle: Path | None = None


def build_ssl_context(policy: TlsPolicy) -> ssl.SSLContext:
    """Build an SSL context from the configured TLS verification policy."""

    if not policy.verify:
        return ssl._create_unverified_context()

    if policy.ca_bundle is not None:
        return ssl.create_default_context(cafile=str(policy.ca_bundle))

    return ssl.create_default_context()
