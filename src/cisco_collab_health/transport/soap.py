"""Shared SOAP transport for CUCM API collectors."""

from __future__ import annotations

import base64
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cisco_collab_health.collectors.base import CollectionContext
from cisco_collab_health.transport.tls import build_ssl_context

SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"


@dataclass(frozen=True)
class SoapRequest:
    """A SOAP request plus artifact routing metadata."""

    endpoint: str
    body: str
    operation: str
    interface: str
    node: str
    namespace: str | None = None
    action: str | None = None
    namespace_prefix: str | None = None
    artifact_operation: str | None = None


@dataclass(frozen=True)
class SoapResponse:
    """SOAP response data returned by the transport."""

    status: int | None
    reason: str | None
    headers: dict[str, str]
    body: str
    operation: str
    interface: str
    artifact_request: str
    artifact_response: str
    request_artifact_path: Path | None = None
    response_artifact_path: Path | None = None


class SoapTransportError(RuntimeError):
    """Base class for SOAP transport failures."""


class SoapHttpError(SoapTransportError):
    """Raised when an HTTP error response is returned."""

    def __init__(
        self,
        *,
        status: int,
        reason: str,
        body: str,
        artifact_response: str,
        request_artifact_path: Path | None = None,
        response_artifact_path: Path | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.body = body
        self.artifact_response = artifact_response
        self.request_artifact_path = request_artifact_path
        self.response_artifact_path = response_artifact_path
        super().__init__(f"HTTP {status}: {reason}")


class SoapClient:
    """Sends SOAP requests with shared TLS, auth, and artifact behavior."""

    def send(self, request: SoapRequest, context: CollectionContext) -> SoapResponse:
        envelope = soap_envelope(
            request.body,
            namespace=request.namespace,
            namespace_prefix=request.namespace_prefix,
        )
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
        }
        if request.action is not None:
            headers["SOAPAction"] = request.action

        artifact_request = format_http_request(request.endpoint, headers=headers, body=envelope)
        http_request = urllib.request.Request(
            request.endpoint,
            data=envelope.encode("utf-8"),
            headers={
                **self._auth_headers(context),
                **headers,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                http_request,
                timeout=context.timeout_seconds,
                context=build_ssl_context(context.tls),
            ) as response:
                response_text = response.read().decode("utf-8", errors="replace")
                response_artifact = format_http_response(
                    status=getattr(response, "status", None),
                    reason=getattr(response, "reason", None),
                    headers=getattr(response, "headers", None),
                    body=response_text,
                )
        except urllib.error.HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            response_artifact = format_http_response(
                status=exc.code,
                reason=exc.reason,
                headers=exc.headers,
                body=response_text,
            )
            request_path, response_path = self._write_artifact(
                request,
                context,
                artifact_request,
                response_artifact,
            )
            raise SoapHttpError(
                status=exc.code,
                reason=str(exc.reason),
                body=response_text,
                artifact_response=response_artifact,
                request_artifact_path=request_path,
                response_artifact_path=response_path,
            ) from exc
        except urllib.error.URLError as exc:
            response_artifact = f"TRANSPORT ERROR\n{exc.reason}\n"
            self._write_artifact(request, context, artifact_request, response_artifact)
            raise SoapTransportError(str(exc.reason)) from exc
        except OSError as exc:
            response_artifact = f"OS ERROR\n{exc}\n"
            self._write_artifact(request, context, artifact_request, response_artifact)
            raise SoapTransportError(str(exc)) from exc

        request_path, response_path = self._write_artifact(
            request,
            context,
            artifact_request,
            response_artifact,
        )
        return SoapResponse(
            status=getattr(response, "status", None),
            reason=getattr(response, "reason", None),
            headers=dict(getattr(response, "headers", {}) or {}),
            body=response_text,
            operation=request.operation,
            interface=request.interface,
            artifact_request=artifact_request,
            artifact_response=response_artifact,
            request_artifact_path=request_path,
            response_artifact_path=response_path,
        )

    def _auth_headers(self, context: CollectionContext) -> dict[str, str]:
        if not context.gui_username or not context.gui_password:
            return {}
        credentials = f"{context.gui_username}:{context.gui_password}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(credentials).decode("ascii")}

    def _write_artifact(
        self,
        request: SoapRequest,
        context: CollectionContext,
        artifact_request: str,
        artifact_response: str,
    ) -> tuple[Path | None, Path | None]:
        store = context.artifact_store
        if store is None:
            return None, None
        return store.write_api_exchange(
            request.node,
            request.interface,
            request.artifact_operation or request.operation,
            request=artifact_request,
            response=artifact_response,
        )


def soap_envelope(
    body: str,
    *,
    namespace: str | None = None,
    namespace_prefix: str | None = None,
) -> str:
    namespace_declaration = ""
    if namespace and namespace_prefix:
        namespace_declaration = f' xmlns:{namespace_prefix}="{namespace}"'

    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAP_NAMESPACE}"{namespace_declaration}>
  <soapenv:Body>
    {body}
  </soapenv:Body>
</soapenv:Envelope>
"""


def format_http_request(endpoint: str, *, headers: dict[str, str], body: str) -> str:
    header_lines = "\n".join(f"{name}: {value}" for name, value in sorted(headers.items()))
    return f"POST {endpoint} HTTP/1.1\n{header_lines}\n\n{body}"


def format_http_response(
    *,
    status: int | None,
    reason: str | None,
    headers: object,
    body: str,
) -> str:
    status_line = f"HTTP {status or 'unknown'}"
    if reason:
        status_line = f"{status_line} {reason}"
    header_lines = format_response_headers(headers)
    if header_lines:
        return f"{status_line}\n{header_lines}\n\n{body}"
    return f"{status_line}\n\n{body}"


def format_response_headers(headers: object) -> str:
    if headers is None:
        return ""
    if hasattr(headers, "items"):
        return "\n".join(f"{name}: {value}" for name, value in headers.items())
    return str(headers).strip()
