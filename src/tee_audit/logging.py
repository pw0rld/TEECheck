"""Structured logging configuration for tee-audit."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Simple JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def configure_logging(log_file: Path | None = None, verbose: bool = False) -> None:
    """Configure structured logging for the audit pipeline.

    Uses stdlib logging with JSON formatter. No external dependencies.
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Console handler — human-readable
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    handlers: list[logging.Handler] = [console_handler]

    # File handler — JSON structured
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JsonFormatter())
        handlers.append(file_handler)

    # Configure root logger
    root_logger = logging.getLogger("tee_audit")
    root_logger.setLevel(logging.DEBUG)
    root_logger.handlers.clear()
    for handler in handlers:
        root_logger.addHandler(handler)
