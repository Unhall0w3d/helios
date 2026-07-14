"""Terminal status messages for AletheiaUC runs."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from threading import Lock
from typing import TextIO


COLORS = {
    "INFO": "\033[36m",
    "OK": "\033[32m",
    "WARN": "\033[33m",
    "FAIL": "\033[31m",
    "STAGE": "\033[35m",
}
RESET = "\033[0m"


@dataclass
class StatusPrinter:
    """Prints concise bracketed status messages without leaking raw command output."""

    stream: TextIO = sys.stderr
    use_color: bool | None = None
    log_stream: TextIO | None = None
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def attach_log_stream(self, log_stream: TextIO) -> None:
        self.log_stream = log_stream

    def stage(self, message: str) -> None:
        self.emit("STAGE", message)

    def info(self, message: str) -> None:
        self.emit("INFO", message)

    def ok(self, message: str) -> None:
        self.emit("OK", message)

    def warn(self, message: str) -> None:
        self.emit("WARN", message)

    def fail(self, message: str) -> None:
        self.emit("FAIL", message)

    def emit(self, level: str, message: str) -> None:
        plain_label = f"[{level}]"
        label = plain_label
        if self._should_color():
            label = f"{COLORS.get(level, '')}{label}{RESET}"
        with self._lock:
            print(f"{label} {message}", file=self.stream, flush=True)
            if self.log_stream is not None:
                print(f"{plain_label} {message}", file=self.log_stream, flush=True)

    def _should_color(self) -> bool:
        if self.use_color is not None:
            return self.use_color
        return self.stream.isatty()
