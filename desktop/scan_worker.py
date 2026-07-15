"""
Background scan worker for the Warden desktop app.

Runs core.scanner.run_scan() on a QThread so the UI stays responsive
during long scans, and defensively catches every exception so a scan
failure surfaces as a signal the UI can display — it can never crash the
application outright.
"""
from __future__ import annotations

import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from core.logging_config import get_logger
from core.scanner import ScanResult, run_scan

logger = get_logger("desktop.worker")


class ScanWorker(QObject):
    """Lives inside a QThread; do not touch widgets directly from its slots."""

    progress = Signal(int, str)        # files_scanned, current_path
    log_line = Signal(str, str)        # message, level ("dim"|"warn"|"error"|"ok")
    finished = Signal(object)          # ScanResult
    failed = Signal(str)               # fatal error message (setup-time only)

    def __init__(self, params: dict):
        super().__init__()
        self._params = params
        self._cancelled = False
        self._files_scanned = 0

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        """Entry point invoked once the owning QThread starts."""
        try:
            self._run_inner()
        except Exception as e:  # absolute last line of defense
            logger.error("Unhandled exception in scan worker: %s\n%s", e, traceback.format_exc())
            self.failed.emit(f"Unexpected error: {e}")

    def _run_inner(self) -> None:
        params = self._params
        target_display = params.get("target", "")
        self.log_line.emit(f"Scanning {target_display}", "dim")
        self.log_line.emit(f"Modules: {', '.join(params['modules'])}", "dim")

        class _Cancelled(Exception):
            pass

        def progress_cb(path: str) -> None:
            if self._cancelled:
                raise _Cancelled()
            self._files_scanned += 1
            n = self._files_scanned
            if n % 25 == 0:
                self.log_line.emit(f"...{n} files scanned (current: {path})", "dim")
            self.progress.emit(n, path)

        def error_cb(message: str) -> None:
            logger.warning(message)
            self.log_line.emit(message, "warn")

        try:
            result: ScanResult = run_scan(
                target_dir=params["target_dir"],
                modules=params["modules"],
                enable_entropy=params["enable_entropy"],
                scan_pe_strings=params["scan_pe_strings"],
                services_file=params["services_file"] or None,
                use_osslsigncode=params["use_osslsigncode"],
                single_file=params["single_file"],
                vt_api_key=params.get("vt_api_key") or None,
                vt_include_clean=params.get("vt_include_clean", False),
                vt_upload_unknown=params.get("vt_upload_unknown", False),
                progress_callback=progress_cb,
                error_callback=error_cb,
            )
        except _Cancelled:
            self.log_line.emit("Scan cancelled by user.", "warn")
            self.finished.emit(None)
            return
        except FileNotFoundError as e:
            logger.warning("Scan setup error: %s", e)
            self.log_line.emit(str(e), "error")
            self.failed.emit(str(e))
            return
        except Exception as e:
            logger.error("Scan failed: %s\n%s", e, traceback.format_exc())
            self.log_line.emit(f"Unexpected error: {e}", "error")
            self.failed.emit(f"Unexpected error: {e}")
            return

        if result.module_errors:
            self.log_line.emit(
                f"{len(result.module_errors)} note(s) logged during the scan (see log above) — "
                f"not necessarily failures, findings collected are still valid.",
                "dim",
            )

        counts = result.summary_counts()
        self.log_line.emit(
            "Scan complete. Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()),
            "ok",
        )
        self.finished.emit(result)


class VTTestWorker(QObject):
    """Runs a single VT key-validity check off the UI thread (network call, up to ~20s)."""

    result = Signal(bool, str)

    def __init__(self, api_key: str):
        super().__init__()
        self._api_key = api_key

    def run(self) -> None:
        from core.virustotal_utils import test_api_key
        try:
            ok, message = test_api_key(self._api_key)
        except Exception as e:  # never let this freeze/crash the UI
            ok, message = False, f"Unexpected error: {e}"
        self.result.emit(ok, message)


class ScanController(QObject):
    """
    Owns the QThread/ScanWorker pair and exposes a simple start/cancel API
    to the main window, so MainWindow never has to manage QThread lifetime
    details directly.
    """

    progress = Signal(int, str)
    log_line = Signal(str, str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self):
        super().__init__()
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(self, params: dict) -> None:
        if self.is_running:
            raise RuntimeError("A scan is already running.")

        self._thread = QThread()
        self._worker = ScanWorker(params)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self.progress)
        self._worker.log_line.connect(self.log_line)
        self._worker.finished.connect(self._on_finished)
        self._worker.failed.connect(self._on_failed)

        self._thread.start()

    def cancel(self) -> None:
        if self._worker:
            self._worker.cancel()

    def _teardown(self) -> None:
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
        self._thread = None
        self._worker = None

    def _on_finished(self, result) -> None:
        self.finished.emit(result)
        self._teardown()

    def _on_failed(self, message: str) -> None:
        self.failed.emit(message)
        self._teardown()
