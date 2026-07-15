#!/usr/bin/env python3
"""
Warden Desktop — PySide6 entry point.

Run with:  python desktop/main.py
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

# Make the project root importable when run as `python desktop/main.py`.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.logging_config import setup_logging, get_logger  # noqa: E402

logger = get_logger("desktop")


def _install_global_exception_hook(app: QApplication) -> None:
    """
    Catch anything that slips past local try/except blocks so the app
    degrades to an error dialog instead of a silent crash or a traceback
    dumped to a console the analyst probably isn't watching.
    """
    def handle_exception(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        formatted = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        logger.critical("Unhandled exception:\n%s", formatted)
        try:
            QMessageBox.critical(
                None,
                "Unexpected error",
                "Warden hit an unexpected error and had to recover.\n\n"
                f"{exc_value}\n\n"
                "Details have been written to the log file "
                "(~/.warden/logs/warden.log). The application will remain open — "
                "please save your work and restart if anything looks wrong.",
            )
        except Exception:
            # If even showing the dialog fails, there's nothing further we
            # can safely do besides making sure the error is on record.
            pass

    sys.excepthook = handle_exception


def main() -> int:
    setup_logging()
    logger.info("Warden desktop starting up")

    app = QApplication(sys.argv)
    app.setApplicationName("Warden")
    app.setOrganizationName("Ankesh Prajapati")

    _install_global_exception_hook(app)

    from desktop.theme import QSS
    app.setStyleSheet(QSS)

    # Imported after QApplication exists — some Qt widget setup wants an
    # active application instance in place first.
    from desktop.main_window import MainWindow

    window = MainWindow()
    window.show()

    logger.info("Warden desktop UI ready")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
