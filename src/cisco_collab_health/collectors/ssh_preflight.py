"""Sequential SSH trust preflight and bounded node collection helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Protocol, TypeVar

from cisco_collab_health.config import normalize_node_address
from cisco_collab_health.models.runtime import CollectionContext
from cisco_collab_health.transport.ssh import is_ssh_authentication_failure


T = TypeVar("T")


class SshSession(Protocol):
    def __enter__(self) -> "SshSession": ...
    def __exit__(self, *_: object) -> None: ...


SessionFactory = Callable[[CollectionContext], SshSession]


def preflight_ssh_nodes(
    context: CollectionContext,
    nodes: Iterable[str],
    session_factory: SessionFactory,
) -> tuple[list[CollectionContext], list[str]]:
    """Open and close every node serially, allowing one key prompt at a time."""

    ready: list[CollectionContext] = []
    warnings: list[str] = []
    planned_nodes = tuple(dict.fromkeys(item for item in nodes if item))
    for index, node in enumerate(planned_nodes, start=1):
        node_context = replace(
            context,
            target=node,
            publisher_ip=node,
            os_password=context.node_platform_passwords.get(
                normalize_node_address(node), context.os_password
            ),
        )
        _progress(
            context,
            f"SSH preflight {index}/{len(planned_nodes)}: {node} (trust, authenticate, open shell)",
        )
        try:
            with session_factory(node_context):
                pass
        except Exception as exc:
            retried_context = _retry_authentication(
                context, node_context, node, exc, session_factory
            )
            if retried_context is None:
                warnings.append(f"SSH preflight failed on {node}: {exc}")
                _progress(context, f"SSH preflight failed: {node}")
                continue
            node_context = retried_context
            _progress(context, f"SSH preflight complete after password retry: {node}")
        else:
            _progress(context, f"SSH preflight complete: {node}")
        # The worker pool must never prompt or enroll a key. It uses the
        # key just validated and saved by this serial preflight instead.
        ready.append(
            replace(
                node_context,
                accept_new_host_key=False,
                host_key_approval=None,
                ssh_password_retry=None,
            )
        )
    return ready, warnings


def _retry_authentication(
    context: CollectionContext,
    node_context: CollectionContext,
    node: str,
    exc: Exception,
    session_factory: SessionFactory,
) -> CollectionContext | None:
    if context.ssh_password_retry is None or not is_ssh_authentication_failure(exc):
        return None
    _progress(context, f"SSH authentication failed on {node}; requesting a node-specific password")
    password = context.ssh_password_retry(node, str(exc))
    if password is None:
        _progress(context, f"SSH password retry skipped: {node}")
        return None
    retry_context = replace(node_context, os_password=password)
    _progress(context, f"SSH preflight retry: {node} (authenticate, open shell)")
    try:
        with session_factory(retry_context):
            pass
    except Exception:
        _progress(context, f"SSH password retry failed: {node}")
        return None
    context.node_platform_passwords[normalize_node_address(node)] = password
    return retry_context


def collect_preflighted_nodes(
    contexts: Iterable[CollectionContext],
    workers: int,
    collect_one: Callable[[CollectionContext], T],
) -> list[T]:
    """Collect independent nodes concurrently while preserving input result order."""

    ordered_contexts = list(contexts)
    if len(ordered_contexts) < 2 or workers <= 1:
        return [_collect_with_progress(context, collect_one) for context in ordered_contexts]
    with ThreadPoolExecutor(max_workers=min(workers, len(ordered_contexts))) as executor:
        futures = [
            executor.submit(_collect_with_progress, context, collect_one)
            for context in ordered_contexts
        ]
        return [future.result() for future in futures]


def _collect_with_progress(
    context: CollectionContext, collect_one: Callable[[CollectionContext], T]
) -> T:
    node = context.publisher_ip or context.target or "unknown"
    _progress(context, f"SSH CLI worker started: {node}")
    try:
        return collect_one(context)
    finally:
        _progress(context, f"SSH CLI worker finished: {node}")


def _progress(context: CollectionContext, message: str) -> None:
    if context.progress is not None:
        context.progress(message)
