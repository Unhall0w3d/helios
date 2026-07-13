"""Assessment artifact storage.

Artifacts are local run evidence for parsers, debugging, and future report
traceability. They should not contain reusable credentials.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from zipfile import ZIP_DEFLATED, ZipFile
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, TextIO

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


class ArtifactRedactionMode(str, Enum):
    """Controls how much sensitive content is removed from written artifacts."""

    NONE = "none"
    SECRETS = "secrets"


@dataclass(frozen=True)
class ArtifactStore:
    """Writes assessment artifacts into a per-run local directory."""

    root: Path
    run_id: str
    profile_name: str
    redaction_mode: ArtifactRedactionMode = ArtifactRedactionMode.SECRETS

    @classmethod
    def create(
        cls,
        root_dir: str | Path,
        profile_name: str,
        started_at: datetime | None = None,
        redaction_mode: str | ArtifactRedactionMode = ArtifactRedactionMode.SECRETS,
    ) -> "ArtifactStore":
        run_time = started_at or datetime.now()
        base_run_id = run_time.strftime("%Y%m%d-%H%M%S-%f")
        root, run_id = _create_unique_run_directory(
            Path(root_dir).expanduser() / _safe_name(profile_name),
            base_run_id,
        )
        return cls(
            root=root,
            run_id=run_id,
            profile_name=profile_name,
            redaction_mode=ArtifactRedactionMode(redaction_mode),
        )

    def write_manifest(self, metadata: dict[str, Any]) -> Path:
        payload = _existing_manifest(self.root / "manifest.json") | {
            "run_id": self.run_id,
            "profile_name": self.profile_name,
            **metadata,
        }
        return self.write_json("manifest.json", payload)

    def write_json(self, relative_path: str | Path, payload: Any) -> Path:
        path = self.root / relative_path
        _create_private_directory(path.parent)
        path.write_text(
            json.dumps(_to_jsonable(payload), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _make_private(path)
        return path

    def write_text(self, relative_path: str | Path, content: str) -> Path:
        path = self.root / relative_path
        _create_private_directory(path.parent)
        path.write_text(content, encoding="utf-8")
        _make_private(path)
        return path

    def write_node_json(self, node: str, category: str, filename: str, payload: Any) -> Path:
        return self.write_json(
            Path("nodes") / _safe_name(node) / _category_path(category) / filename,
            payload,
        )

    def write_node_text(self, node: str, category: str, filename: str, content: str) -> Path:
        return self.write_text(
            Path("nodes") / _safe_name(node) / _category_path(category) / filename,
            content,
        )

    def write_api_exchange(
        self,
        node: str,
        interface: str,
        operation: str,
        *,
        request: str,
        response: str,
    ) -> tuple[Path, Path]:
        category = Path("api") / _safe_name(interface) / _safe_name(operation)
        request_path = self.write_node_text(
            node,
            str(category),
            "request.txt",
            _sanitize_artifact_text(request, self.redaction_mode),
        )
        response_path = self.write_node_text(
            node,
            str(category),
            "response.txt",
            _sanitize_artifact_text(response, self.redaction_mode),
        )
        return request_path, response_path

    def write_command_output(self, node: str, command: str, output: str) -> Path:
        filename = f"{_safe_name(command)}.txt"
        content = (
            f"$ {command}\n\n{_sanitize_artifact_text(output, self.redaction_mode).rstrip()}\n"
        )
        return self.write_node_text(node, "cli", filename, content)

    def record_operation_attempt(self, payload: dict[str, Any]) -> Path:
        """Append one API/HTTP attempt to the run diagnostic manifest."""

        path = self.root / "operation_attempts.jsonl"
        _create_private_directory(path.parent)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(_to_jsonable(payload), sort_keys=True) + "\n")
        _make_private(path)
        return path


@dataclass(frozen=True)
class RunLogStore:
    """Writes troubleshooting logs for one AletheiaUC run."""

    root: Path
    run_id: str
    profile_name: str

    @classmethod
    def create(
        cls,
        root_dir: str | Path,
        profile_name: str,
        started_at: datetime | None = None,
    ) -> "RunLogStore":
        run_time = started_at or datetime.now()
        base_run_id = run_time.strftime("%Y%m%d-%H%M%S-%f")
        root, run_id = _create_unique_run_directory(
            Path(root_dir).expanduser(),
            base_run_id,
        )
        return cls(root=root, run_id=run_id, profile_name=profile_name)

    @property
    def run_log_path(self) -> Path:
        return self.root / "run.log"

    def open_run_log(self) -> TextIO:
        _create_private_directory(self.root)
        stream = self.run_log_path.open("a", encoding="utf-8")
        _make_private(self.run_log_path)
        return stream

    def write_manifest(self, metadata: dict[str, Any]) -> Path:
        payload = _existing_manifest(self.root / "manifest.json") | {
            "run_id": self.run_id,
            "profile_name": self.profile_name,
            **metadata,
        }
        return self.write_json("manifest.json", payload)

    def write_json(self, relative_path: str | Path, payload: Any) -> Path:
        path = self.root / relative_path
        _create_private_directory(path.parent)
        path.write_text(
            json.dumps(_to_jsonable(payload), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _make_private(path)
        return path

    def write_text(self, relative_path: str | Path, content: str) -> Path:
        path = self.root / relative_path
        _create_private_directory(path.parent)
        path.write_text(content, encoding="utf-8")
        _make_private(path)
        return path

    def copy_file(self, source: Path, relative_path: str | Path) -> Path:
        destination = self.root / relative_path
        _create_private_directory(destination.parent)
        shutil.copy2(source, destination)
        _make_private(destination)
        return destination

    def copy_artifact_tree(self, source_root: Path, relative_path: str | Path) -> Path:
        """Copy one run's raw and normalized artifacts into the log bundle."""

        destination = self.root / relative_path
        _create_private_directory(destination)
        if not source_root.exists():
            return destination

        for source in sorted(source_root.rglob("*")):
            if not source.is_file():
                continue
            target = destination / source.relative_to(source_root)
            _create_private_directory(target.parent)
            shutil.copy2(source, target)
            _make_private(target)
        return destination


def export_review_zip(
    store: RunLogStore,
    downloads_dir: str | Path | None = None,
) -> Path:
    """Export one self-contained troubleshooting bundle to the Downloads folder."""

    destination = (
        Path(downloads_dir).expanduser() if downloads_dir is not None else Path.home() / "Downloads"
    )
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = destination / (
        f"aletheiauc-review-{_safe_name(store.profile_name)}-{store.run_id}.zip"
    )
    temporary_path = zip_path.with_suffix(".zip.tmp")
    try:
        with ZipFile(temporary_path, "w", compression=ZIP_DEFLATED) as archive:
            for path in sorted(store.root.rglob("*")):
                if path.is_file():
                    archive.write(
                        path,
                        arcname=Path("logs") / store.run_id / path.relative_to(store.root),
                    )
        _make_private(temporary_path)
        temporary_path.replace(zip_path)
        _make_private(zip_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return zip_path


def write_preflight_artifacts(store: ArtifactStore, publisher: str, preflight: Any) -> Path:
    """Write Publisher preflight evidence for parser/debug review."""

    return store.write_node_json(
        publisher,
        "preflight",
        "publisher_preflight.json",
        preflight,
    )


def write_assessment_artifacts(store: ArtifactStore, report: Any) -> list[Path]:
    """Write normalized assessment outputs for parser/report development."""

    paths = [store.write_json("normalized/assessment_report.json", report)]
    for result in report.collector_results:
        collector_name = getattr(result, "collector_name", "unknown_collector")
        paths.append(
            store.write_json(
                Path("normalized") / "collectors" / f"{_safe_name(collector_name)}.json",
                result,
            )
        )

    for node in report.facts.nodes:
        paths.append(
            store.write_node_json(
                node.address,
                "normalized",
                "node_facts.json",
                node,
            )
        )

    return paths


def write_log_bundle(
    store: RunLogStore,
    *,
    report: Any,
    summary_text: str,
    artifact_store: ArtifactStore | None,
    html_report_path: Path | None,
    customer_safe_html_report_path: Path | None = None,
) -> list[Path]:
    """Write troubleshooting files that are easy to share for analysis."""

    from cisco_collab_health.reports.html import HtmlReportBuilder, available_report_templates

    installed_templates = available_report_templates()

    metadata = getattr(report, "runtime_metadata", {})
    store.write_manifest(
        {
            "sensitivity_classification": "private diagnostic",
            "raw_evidence_included": artifact_store is not None,
            "artifact_redaction": metadata.get("artifact_redaction"),
            "tls_verification": metadata.get("tls_verification"),
            "ssh_host_key_enrollment": metadata.get("ssh_accept_new_host_key", False),
            "customer_safe_report": metadata.get("customer_safe_report", False),
            "customer_safe_html_included": bool(customer_safe_html_report_path),
            "review_report_variants": [
                f"reports/{theme}/{audience}.html"
                for theme in installed_templates
                for audience in ("engineering", "customer-facing")
            ],
            "target_technologies": sorted(
                {
                    target.get("technology")
                    for target in metadata.get("targets", [])
                    if isinstance(target, dict) and target.get("technology")
                }
            ),
            "generated_at": datetime.now().astimezone().isoformat(),
        }
    )
    paths = [
        store.write_text("executive_summary.txt", summary_text),
        store.write_json("assessment_report.json", report),
        store.write_json("collector_warnings.json", _collector_warnings(report)),
    ]
    # Review bundles intentionally include both report audiences for every
    # installed theme. This lets report development compare presentation only;
    # all variants are rendered from the exact same normalized assessment data.
    for theme in installed_templates:
        paths.append(
            store.write_text(
                Path("reports") / theme / "engineering.html",
                HtmlReportBuilder(template=theme).build(report),
            )
        )
        paths.append(
            store.write_text(
                Path("reports") / theme / "customer-facing.html",
                HtmlReportBuilder(customer_safe=True, template=theme).build(report),
            )
        )
    if artifact_store is not None:
        copied_root = store.copy_artifact_tree(artifact_store.root, "artifacts")
        paths.append(
            store.write_text(
                "artifact_index.txt",
                "\n".join(_artifact_index(copied_root, base=copied_root)) + "\n",
            )
        )
        paths.append(
            store.write_text(
                "artifact_source.txt",
                f"Original assessment artifact root: {artifact_store.root}\n"
                f"Copied troubleshooting artifact root: {copied_root}\n",
            )
        )
    if html_report_path is not None and html_report_path.exists():
        paths.append(store.copy_file(html_report_path, "report.html"))
    if customer_safe_html_report_path is not None and customer_safe_html_report_path.exists():
        paths.append(store.copy_file(customer_safe_html_report_path, "customer_safe_report.html"))
    return paths


def _safe_name(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return sanitized.strip("._") or "unknown"


def _existing_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _sanitize_artifact_text(content: str, mode: ArtifactRedactionMode) -> str:
    if mode is ArtifactRedactionMode.NONE:
        return content
    return _redact_secret_values(content)


def _redact_secret_values(content: str) -> str:
    content = re.sub(
        r"(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-csrf-token|x-auth-token|x-api-key):.*$",
        lambda match: f"{match.group(1)}: <redacted>",
        content,
    )
    content = re.sub(
        r"(<[^>]*(?:password|passwd|secret|token)[^>]*>)(.*?)(</[^>]+>)",
        r"\1<redacted>\3",
        content,
        flags=re.IGNORECASE | re.DOTALL,
    )
    content = re.sub(
        r"""(?ix)
        ((?:["'])(?:password|passwd|secret|token|api[_-]?key)(?:["'])\s*:\s*)
        (
            "(?:\\.|[^"\\])*"
            | '(?:\\.|[^'\\])*'
            | [^\s,}\]]+
        )
        """,
        r'\1"<redacted>"',
        content,
    )
    content = re.sub(
        r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*)([^\s,;]+)",
        r"\1<redacted>",
        content,
    )
    content = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer <redacted>", content)
    content = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1<redacted>@", content)
    return re.sub(
        r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.+?-----END [^-]*PRIVATE KEY-----",
        "<redacted private key>",
        content,
    )


def _create_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(_PRIVATE_DIRECTORY_MODE)


def _create_unique_run_directory(parent: Path, base_run_id: str) -> tuple[Path, str]:
    """Create a private run directory without ever reusing an earlier run."""

    _create_private_directory(parent)
    suffix = 0
    while True:
        run_id = base_run_id if suffix == 0 else f"{base_run_id}-{suffix:02d}"
        path = parent / run_id
        try:
            path.mkdir()
        except FileExistsError:
            suffix += 1
            continue
        if os.name == "posix":
            path.chmod(_PRIVATE_DIRECTORY_MODE)
        return path, run_id


def _make_private(path: Path) -> None:
    if os.name == "posix" and path.exists():
        path.chmod(_PRIVATE_FILE_MODE)


def _collector_warnings(report: Any) -> list[dict[str, Any]]:
    warnings = []
    for result in getattr(report, "collector_results", []):
        collector_name = getattr(result, "collector_name", "unknown_collector")
        for warning in getattr(result, "warnings", []):
            warnings.append({"collector": collector_name, "type": "warning", "message": warning})
        for error in getattr(result, "errors", []):
            warnings.append(
                {
                    "collector": collector_name,
                    "type": "error",
                    "message": getattr(error, "message", ""),
                    "exception_type": getattr(error, "exception_type", "Exception"),
                    "recoverable": getattr(error, "recoverable", True),
                }
            )
    return warnings


def _artifact_index(root: Path, *, base: Path | None = None) -> list[str]:
    if not root.exists():
        return []
    base_path = base or root
    return [
        str(path.relative_to(base_path) if path.is_relative_to(base_path) else path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def _category_path(value: str) -> Path:
    parts = Path(value).parts
    return Path(*(_safe_name(part) for part in parts if part not in {"", "."}))


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _to_jsonable(asdict(value))
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_jsonable(item) for item in value]
    return value
