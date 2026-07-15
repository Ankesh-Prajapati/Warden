"""
Centralized logging configuration for Warden.

Every entry point (cli.py, desktop/main.py) calls
`setup_logging()` once at startup so all modules log through the same
rotating file handler instead of each printing ad-hoc to stdout. This is
what lets a scan session be reconstructed after the fact when something
goes wrong on an analyst's machine, without anyone needing to reproduce
the issue live.
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

DEFAULT_LOG_DIR = Path.home() / ".warden" / "logs"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def setup_logging(
    log_dir: Path | str | None = None,
    level: int = logging.INFO,
    console: bool = True,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Configure the root "warden" logger once per process.

    Safe to call multiple times — only the first call takes effect, so
    every entry point can call it unconditionally at startup without
    worrying about double-attaching handlers.

    Returns the "warden" logger for convenience.
    """
    global _configured
    root = logging.getLogger("warden")

    if _configured:
        return root

    root.setLevel(level)
    root.propagate = False

    log_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / "warden.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        file_handler.setLevel(level)
        root.addHandler(file_handler)
    except OSError:
        # If the log directory genuinely can't be created (read-only
        # filesystem, permissions issue) fall back to console-only rather
        # than crashing the whole application over logging infrastructure.
        console = True

    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
        console_handler.setLevel(level)
        root.addHandler(console_handler)

    _configured = True
    root.info("Logging initialized (dir=%s, level=%s)", log_dir, logging.getLevelName(level))
    return root


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the "warden" namespace, e.g. warden.scanner."""
    return logging.getLogger(f"warden.{name}")
