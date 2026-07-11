"""Captured HTTP GET transport for diagnostic interface discovery."""

from __future__ import annotations

import base64
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import cast

from cisco_collab_health.artifacts import ArtifactStore
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.soap import format_http_response
from cisco_collab_health.transport.tls import build_ssl_context


@dataclass(frozen=True)
class CapturedHttpResponse:
    """Captured HTTP response and evidence path."""

    status: int
    reason: str | None
    body: str
    response_artifact_path: Path | None


class CapturedHttpError(RuntimeError):
    """Raised after an unsuccessful HTTP response has been captured."""


class CapturedHttpClient:
    """Perform GET requests while retaining sanitized request/response artifacts."""

    def get(
        self,
        endpoint: str,
        context: CollectionContext,
        *,
        node: str,
        interface: str,
        operation: str,
        credential_kind: str = "gui",
    ) -> CapturedHttpResponse:
        started_at = datetime.now(UTC)
        started_clock = monotonic()
        headers = self._auth_headers(context, credential_kind)
        headers["Accept"] = "application/json"
        artifact_request = f"GET {endpoint} HTTP/1.1\n\n"
        request = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(
                request,
                timeout=context.timeout_seconds,
                context=build_ssl_context(context.tls),
            ) as response:
                body = response.read().decode("utf-8", errors="replace")
                status = int(getattr(response, "status", 200))
                reason = str(getattr(response, "reason", "") or "") or None
                artifact_response = format_http_response(
                    status=status,
                    reason=reason,
                    headers=getattr(response, "headers", None),
                    body=body,
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            artifact_response = format_http_response(
                status=exc.code,
                reason=str(exc.reason),
                headers=exc.headers,
                body=body,
            )
            self._write_artifacts(
                context,
                node=node,
                interface=interface,
                operation=operation,
                endpoint=endpoint,
                request=artifact_request,
                response=artifact_response,
                started_at=started_at,
                duration_seconds=monotonic() - started_clock,
                outcome="http_error",
                status=exc.code,
                reason=str(exc.reason),
            )
            raise CapturedHttpError(f"HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, OSError) as exc:
            reason_value = getattr(exc, "reason", exc)
            artifact_response = f"TRANSPORT ERROR\n{reason_value}\n"
            self._write_artifacts(
                context,
                node=node,
                interface=interface,
                operation=operation,
                endpoint=endpoint,
                request=artifact_request,
                response=artifact_response,
                started_at=started_at,
                duration_seconds=monotonic() - started_clock,
                outcome="transport_error",
                reason=str(reason_value),
            )
            raise CapturedHttpError(str(reason_value)) from exc

        _, response_path = self._write_artifacts(
            context,
            node=node,
            interface=interface,
            operation=operation,
            endpoint=endpoint,
            request=artifact_request,
            response=artifact_response,
            started_at=started_at,
            duration_seconds=monotonic() - started_clock,
            outcome="success",
            status=status,
            reason=reason,
        )
        return CapturedHttpResponse(status, reason, body, response_path)

    def _auth_headers(self, context: CollectionContext, credential_kind: str) -> dict[str, str]:
        username = context.os_username if credential_kind == "os" else context.gui_username
        password = context.os_password if credential_kind == "os" else context.gui_password
        if not username or not password:
            return {}
        value = f"{username}:{password}".encode()
        return {"Authorization": "Basic " + base64.b64encode(value).decode("ascii")}

    def _write_artifacts(
        self,
        context: CollectionContext,
        *,
        node: str,
        interface: str,
        operation: str,
        endpoint: str,
        request: str,
        response: str,
        started_at: datetime,
        duration_seconds: float,
        outcome: str,
        status: int | None = None,
        reason: str | None = None,
    ) -> tuple[Path | None, Path | None]:
        if context.artifact_store is None:
            return None, None
        store = cast(ArtifactStore, context.artifact_store)
        paths = store.write_api_exchange(
            node,
            interface,
            operation,
            request=request,
            response=response,
        )
        store.record_operation_attempt(
            {
                "interface": interface,
                "operation": operation,
                "artifact_operation": operation,
                "node": node,
                "endpoint": endpoint,
                "started_at": started_at,
                "duration_seconds": round(duration_seconds, 6),
                "outcome": outcome,
                "http_status": status,
                "reason": reason,
                "request_bytes": len(request.encode("utf-8")),
                "response_bytes": len(response.encode("utf-8")),
                "request_artifact_path": paths[0],
                "response_artifact_path": paths[1],
            }
        )
        return paths
