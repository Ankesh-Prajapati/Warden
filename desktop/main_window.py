"""Main window for the Warden desktop application."""
from __future__ import annotations

import html
import json
import sys
import traceback
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer
from PySide6.QtGui import QAction, QActionGroup, QColor, QIcon, QPalette
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QSpinBox,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.logging_config import get_logger
from core.finding_grouping import group_findings
from core.models import Finding
from report.html_export import generate_html_report

from desktop.finding_dialog import FindingDialog
from desktop.scan_worker import ScanController, VTTestWorker
from desktop.settings import WardenSettings
from desktop import theme
from desktop.theme import SEVERITY_COLORS, set_theme

logger = get_logger("desktop.main_window")


def _application_root() -> Path:
    """Return the installed app folder, or the project root when running from source."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


REPORTS_DIR = _application_root() / "reports"

COMMON_MODULES = [
    ("secrets", "Secrets && Config Exposure"),
    ("dll_hijack", "DLL Hijacking Detection"),
    ("signature", "Signature / Integrity Check"),
    ("re_exposure", "RE / Anti-Tamper Exposure"),
]
PLATFORM_MODULES = [
    ("linux", "Linux Thick-Client Assessment"),
    ("macos", "macOS Thick-Client Assessment"),
]

FILE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Warden — Static Security Analysis")
        self.resize(1180, 820)

        icon_path = Path(__file__).resolve().parent.parent / "assets" / "logo.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        self.settings = WardenSettings()
        self.controller = ScanController()
        self.controller.progress.connect(self._on_progress)
        self.controller.log_line.connect(self._on_log_line)
        self.controller.finished.connect(self._on_finished)
        self.controller.failed.connect(self._on_failed)

        self._module_checks: dict[str, QCheckBox] = {}
        self._vt_test_thread: QThread | None = None
        self._vt_test_worker: VTTestWorker | None = None
        self._current_result = None
        self._current_report_html: Path | None = None
        self._current_report_json: Path | None = None
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)
        self._elapsed_seconds = 0

        self._build_ui()
        self._build_menu()
        self._load_settings_into_ui()
        self._update_target_hint()

        geometry = self.settings.load_geometry()
        if geometry:
            self.restoreGeometry(geometry)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        self.menuBar().setNativeMenuBar(False)
        self.menuBar().setObjectName("mainMenuBar")
        self.menuBar().setAutoFillBackground(True)
        self._apply_menu_theme(self.settings.theme_mode)

        file_menu = self.menuBar().addMenu("&File")
        self._apply_popup_menu_theme(file_menu, self.settings.theme_mode)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        theme_menu = self.menuBar().addMenu("&Theme")
        self._apply_popup_menu_theme(theme_menu, self.settings.theme_mode)
        theme_group = QActionGroup(self)
        theme_group.setExclusive(True)
        self._dark_theme_action = QAction("Dark", self, checkable=True)
        self._light_theme_action = QAction("Light", self, checkable=True)
        theme_group.addAction(self._dark_theme_action)
        theme_group.addAction(self._light_theme_action)
        self._dark_theme_action.triggered.connect(lambda: self._set_theme("dark"))
        self._light_theme_action.triggered.connect(lambda: self._set_theme("light"))
        theme_menu.addAction(self._dark_theme_action)
        theme_menu.addAction(self._light_theme_action)
        current_mode = self.settings.theme_mode
        self._dark_theme_action.setChecked(current_mode == "dark")
        self._light_theme_action.setChecked(current_mode == "light")

        help_menu = self.menuBar().addMenu("&Help")
        self._apply_popup_menu_theme(help_menu, self.settings.theme_mode)
        about_action = QAction("About Warden", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _menu_popup_qss(self, mode: str) -> str:
        palette = theme.get_palette(mode)
        return f"""
            QMenu {{
                background-color: {palette["PANEL"]};
                color: {palette["TEXT"]};
                border: 1px solid {palette["BORDER"]};
                padding: 4px;
            }}
            QMenu::item {{
                background: transparent;
                color: {palette["TEXT"]};
                padding: 7px 28px 7px 18px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background-color: {palette["ACCENT_DIM"]};
                color: {palette["TEXT"]};
            }}
            QMenu::item:checked {{
                color: {palette["ACCENT"]};
                font-weight: 700;
            }}
            QMenu::item:disabled {{
                color: {palette["MUTED"]};
            }}
            QMenu::separator {{
                height: 1px;
                background: {palette["BORDER"]};
                margin: 4px 8px;
            }}
        """

    def _apply_popup_menu_theme(self, menu, mode: str) -> None:
        palette = theme.get_palette(mode)
        qpalette = menu.palette()
        qpalette.setColor(QPalette.ColorRole.Window, QColor(palette["PANEL"]))
        qpalette.setColor(QPalette.ColorRole.WindowText, QColor(palette["TEXT"]))
        qpalette.setColor(QPalette.ColorRole.Base, QColor(palette["PANEL"]))
        qpalette.setColor(QPalette.ColorRole.Text, QColor(palette["TEXT"]))
        qpalette.setColor(QPalette.ColorRole.ButtonText, QColor(palette["TEXT"]))
        qpalette.setColor(QPalette.ColorRole.Highlight, QColor(palette["ACCENT_DIM"]))
        qpalette.setColor(QPalette.ColorRole.HighlightedText, QColor(palette["TEXT"]))
        menu.setPalette(qpalette)
        menu.setStyleSheet(self._menu_popup_qss(mode))

    def _apply_menu_theme(self, mode: str) -> None:
        """Apply explicit menu colors; Windows can ignore inherited QSS here."""
        palette = theme.get_palette(mode)
        menu_bar = self.menuBar()

        qpalette = menu_bar.palette()
        qpalette.setColor(QPalette.ColorRole.Window, QColor(palette["PANEL"]))
        qpalette.setColor(QPalette.ColorRole.WindowText, QColor(palette["TEXT"]))
        qpalette.setColor(QPalette.ColorRole.Button, QColor(palette["PANEL"]))
        qpalette.setColor(QPalette.ColorRole.ButtonText, QColor(palette["TEXT"]))
        qpalette.setColor(QPalette.ColorRole.Text, QColor(palette["TEXT"]))
        menu_bar.setPalette(qpalette)

        menu_bar.setStyleSheet(
            f"""
            QMenuBar#mainMenuBar {{
                background-color: {palette["PANEL"]};
                color: {palette["TEXT"]};
                border-bottom: 1px solid {palette["BORDER"]};
                padding: 2px 8px;
            }}
            QMenuBar#mainMenuBar::item {{
                background: transparent;
                color: {palette["TEXT"]};
                padding: 6px 14px;
                margin: 0 2px;
                border-radius: 4px;
            }}
            QMenuBar#mainMenuBar::item:selected,
            QMenuBar#mainMenuBar::item:pressed {{
                background-color: {palette["ACCENT_DIM"]};
                color: {palette["TEXT"]};
            }}
            QMenuBar#mainMenuBar::item:disabled {{
                color: {palette["MUTED"]};
            }}
            """
        )
        for action in menu_bar.actions():
            popup = action.menu()
            if popup is not None:
                self._apply_popup_menu_theme(popup, mode)
        menu_bar.update()

    def _set_theme(self, mode: str) -> None:
        """Switch the app's light/dark theme at runtime and persist the
        choice so it's remembered next launch."""
        from PySide6.QtWidgets import QApplication

        mode = mode if mode in {"dark", "light"} else "dark"
        qss = set_theme(mode)
        app = QApplication.instance()
        if app is not None:
            app.setPalette(theme.build_qpalette(mode))
            app.setStyleSheet(qss)
        self._apply_menu_theme(mode)
        self.settings.theme_mode = mode
        self._dark_theme_action.setChecked(mode == "dark")
        self._light_theme_action.setChecked(mode == "light")
        # Severity colors in theme.SEVERITY_COLORS were updated in place by
        # set_theme(); re-populate the table so already-rendered rows pick
        # up the new palette immediately instead of only on the next scan.
        if getattr(self, "_last_findings", None) is not None:
            self._populate_table(self._last_findings)

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Warden",
            "<b>Warden</b><br>"
            "Static security analysis for thick-client applications.<br><br>"
            "Warden performs offline, static-only security assessment of Windows, "
            "Linux, and macOS desktop applications — hardcoded secrets and config "
            "exposure, DLL hijacking risk, Authenticode signature/integrity checks, "
            "reverse-engineering/anti-tamper exposure, and optional VirusTotal "
            "reputation lookups. No dynamic execution or exploitation tooling is "
            "included; all analysis runs locally against the target files "
            "themselves.<br><br>"
            "Created by Ankesh Prajapati.",
        )

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(self._splitter)

        self._splitter.addWidget(self._build_config_panel())
        self._splitter.addWidget(self._build_results_panel())
        self._splitter.setStretchFactor(0, 0)
        self._splitter.setStretchFactor(1, 1)
        # setSizes() before the window has real on-screen geometry is
        # unreliable in Qt — the splitter negotiates against a 0×0 (or
        # otherwise not-yet-final) size and can end up narrower than
        # intended, which showed up as the left panel rendering half-cut
        # off on first launch until something forced a relayout. Deferring
        # to a 0ms singleShot runs this once the event loop has processed
        # the initial show() and real geometry exists.
        QTimer.singleShot(0, lambda: self._splitter.setSizes([420, 760]))

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_files_label = QLabel("0 files scanned")
        self.status_bar.addPermanentWidget(self.status_files_label)

    def _build_config_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setMinimumWidth(380)
        scroll.setMaximumWidth(520)
        # The config panel (target/modules/options/VirusTotal/run controls)
        # is consistently taller than a typical window — without this, the
        # scrollbar only appears once content is already cut off and is
        # easy to miss entirely, making whole sections (e.g. VirusTotal)
        # look like they don't exist rather than "scroll down for more."
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        heading = QLabel("Warden")
        heading.setObjectName("heading")
        subheading = QLabel("Static security analysis for thick-client applications")
        subheading.setObjectName("subheading")
        subheading.setWordWrap(True)
        layout.addWidget(heading)
        layout.addWidget(subheading)

        # -- Target ---------------------------------------------------
        target_group = QGroupBox("1 · Target")
        tg_layout = QVBoxLayout(target_group)
        row = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("C:\\Apps\\TargetApp  or  /home/user/target_app")
        self.target_input.textChanged.connect(self._on_target_changed)
        row.addWidget(self.target_input, stretch=1)
        tg_layout.addLayout(row)

        btn_row = QHBoxLayout()
        browse_folder_btn = QPushButton("📁 Select Folder")
        browse_folder_btn.clicked.connect(self._browse_folder)
        browse_file_btn = QPushButton("📄 Select EXE")
        browse_file_btn.clicked.connect(self._browse_file)
        btn_row.addWidget(browse_folder_btn)
        btn_row.addWidget(browse_file_btn)
        tg_layout.addLayout(btn_row)

        self.target_hint = QLabel("")
        self.target_hint.setTextFormat(Qt.TextFormat.PlainText)  # target name can be attacker-controlled
        self.target_hint.setObjectName("subheading")
        self.target_hint.setWordWrap(True)
        tg_layout.addWidget(self.target_hint)
        layout.addWidget(target_group)

        # -- Modules ----------------------------------------------------
        modules_group = QGroupBox("2 · Modules (common)")
        mg_layout = QVBoxLayout(modules_group)
        for module_id, label in COMMON_MODULES:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self._module_checks[module_id] = cb
            mg_layout.addWidget(cb)
        layout.addWidget(modules_group)

        platform_group = QGroupBox("2b · Platform-Specific Modules")
        pg_layout = QVBoxLayout(platform_group)
        for module_id, label in PLATFORM_MODULES:
            cb = QCheckBox(label)
            cb.setChecked(False)
            self._module_checks[module_id] = cb
            pg_layout.addWidget(cb)
        layout.addWidget(platform_group)

        # -- Options ------------------------------------------------------
        options_group = QGroupBox("3 · Options")
        og_layout = QVBoxLayout(options_group)
        self.opt_entropy = QCheckBox("Entropy-based secret detection")
        self.opt_entropy.setChecked(True)
        self.opt_pestrings = QCheckBox("Scan embedded strings inside .exe/.dll")
        self.opt_pestrings.setChecked(True)
        self.opt_osslsigncode = QCheckBox("Use osslsigncode for deep signature verification (if installed)")
        self.opt_osslsigncode.setChecked(True)
        self.opt_include_inventory = QCheckBox("Show inventory/pass findings in Linux/macOS scans")
        self.opt_include_inventory.setChecked(True)
        og_layout.addWidget(self.opt_entropy)
        og_layout.addWidget(self.opt_pestrings)
        og_layout.addWidget(self.opt_osslsigncode)
        og_layout.addWidget(self.opt_include_inventory)

        services_label = QLabel("Services file (optional — sc query / wmic output):")
        services_label.setObjectName("subheading")
        og_layout.addWidget(services_label)
        self.services_input = QLineEdit()
        self.services_input.setPlaceholderText("/path/to/services_dump.txt")
        og_layout.addWidget(self.services_input)
        layout.addWidget(options_group)

        # -- VirusTotal reputation ------------------------------------------
        vt_group = QGroupBox("4 · VirusTotal Reputation Check")
        vt_layout = QVBoxLayout(vt_group)

        vt_desc = QLabel(
            "Cross-checks each binary's SHA-256 hash against VirusTotal. Only the hash is sent "
            "by default — the binary itself never leaves this machine unless upload is enabled below."
        )
        vt_desc.setObjectName("subheading")
        vt_desc.setWordWrap(True)
        vt_layout.addWidget(vt_desc)

        self.opt_reputation = QCheckBox("Enable reputation check for this scan")
        vt_layout.addWidget(self.opt_reputation)

        max_lookups_row = QHBoxLayout()
        max_lookups_label = QLabel("Max binaries to check per scan:")
        self.vt_max_lookups_input = QSpinBox()
        self.vt_max_lookups_input.setRange(1, 500)
        self.vt_max_lookups_input.setValue(15)
        self.vt_max_lookups_input.valueChanged.connect(self._update_vt_eta_label)
        max_lookups_row.addWidget(max_lookups_label)
        max_lookups_row.addWidget(self.vt_max_lookups_input)
        max_lookups_row.addStretch()
        vt_layout.addLayout(max_lookups_row)

        self.vt_eta_label = QLabel("")
        self.vt_eta_label.setObjectName("subheading")
        self.vt_eta_label.setWordWrap(True)
        vt_layout.addWidget(self.vt_eta_label)
        self._update_vt_eta_label()

        vt_key_label = QLabel("VirusTotal API key (stored via OS settings storage — plaintext, "
                               "same as other desktop apps' saved credentials):")
        vt_key_label.setObjectName("subheading")
        vt_key_label.setWordWrap(True)
        vt_layout.addWidget(vt_key_label)
        self.vt_api_key_input = QLineEdit()
        self.vt_api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_api_key_input.setPlaceholderText("Paste your VirusTotal API key")
        vt_layout.addWidget(self.vt_api_key_input)

        vt_test_row = QHBoxLayout()
        self.vt_test_btn = QPushButton("Test Key")
        self.vt_test_btn.clicked.connect(self._test_vt_key)
        vt_test_row.addWidget(self.vt_test_btn)
        vt_test_row.addStretch()
        vt_layout.addLayout(vt_test_row)
        self.vt_test_status = QLabel("")
        self.vt_test_status.setWordWrap(True)
        self.vt_test_status.setObjectName("subheading")
        vt_layout.addWidget(self.vt_test_status)

        self.opt_vt_include_clean = QCheckBox("Also report binaries VirusTotal has seen and NOT flagged")
        vt_layout.addWidget(self.opt_vt_include_clean)

        vt_danger = QWidget()
        vt_danger.setObjectName("dangerBox")
        vt_danger_layout = QVBoxLayout(vt_danger)
        vt_danger_layout.setContentsMargins(14, 12, 14, 12)
        vt_danger_layout.setSpacing(8)
        self.opt_vt_upload = QCheckBox("Upload unknown binaries to VirusTotal for fresh analysis")
        vt_danger_layout.addWidget(self.opt_vt_upload)
        vt_warning = QLabel(
            "⚠ This sends full file content to a third party, not just a hash. Only enable this "
            "if uploading this specific target to VirusTotal is acceptable under your engagement's "
            "confidentiality terms."
        )
        vt_warning.setObjectName("dangerWarningText")
        vt_warning.setWordWrap(True)
        vt_danger_layout.addWidget(vt_warning)
        self.opt_vt_upload_confirm = QCheckBox("I confirm uploading this target's binaries to VirusTotal is authorized")
        self.opt_vt_upload_confirm.setVisible(False)
        vt_danger_layout.addWidget(self.opt_vt_upload_confirm)
        self.opt_vt_upload.toggled.connect(self.opt_vt_upload_confirm.setVisible)
        self.opt_vt_upload.toggled.connect(
            lambda checked: (not checked) and self.opt_vt_upload_confirm.setChecked(False)
        )
        vt_layout.addWidget(vt_danger)

        layout.addWidget(vt_group)
        layout.addStretch()

        scroll.setWidget(panel)

        # -- Run controls: pinned outside the scroll area -------------------
        # These are the primary action controls (Run/Cancel/Report/Export +
        # progress) — they must always be visible regardless of how far the
        # config sections above are scrolled, rather than living at the
        # bottom of the same scrollable content where they could end up
        # just as hidden as the VirusTotal section was.
        footer = QWidget()
        footer.setObjectName("card")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(16, 12, 16, 14)
        footer_layout.setSpacing(8)

        run_row = QHBoxLayout()
        self.run_btn = QPushButton("▶  Run Scan")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(self._start_scan)
        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setObjectName("danger")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_scan)
        run_row.addWidget(self.run_btn)
        run_row.addWidget(self.cancel_btn)
        footer_layout.addLayout(run_row)

        export_row = QHBoxLayout()
        self.open_report_btn = QPushButton("↗  Open Report")
        self.open_report_btn.setEnabled(False)
        self.open_report_btn.clicked.connect(self._open_report)
        self.export_json_btn = QPushButton("⬇  Export JSON")
        self.export_json_btn.setEnabled(False)
        self.export_json_btn.clicked.connect(self._export_json)
        export_row.addWidget(self.open_report_btn)
        export_row.addWidget(self.export_json_btn)
        footer_layout.addLayout(export_row)

        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        # Starts static/empty (matches the post-scan "done" state) — it
        # only switches to indeterminate mode (range 0,0) once a scan
        # actually starts, in _start_scan below. Starting indeterminate
        # here made the bar animate continuously before Run Scan was even
        # clicked, looking like a scan was already in progress at idle.
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.elapsed_label = QLabel("0:00")
        self.elapsed_label.setObjectName("subheading")
        progress_row.addWidget(self.progress_bar, stretch=1)
        progress_row.addWidget(self.elapsed_label)
        footer_layout.addLayout(progress_row)

        outer = QWidget()
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer_layout.addWidget(scroll, stretch=1)
        outer_layout.addWidget(footer)
        # Set directly on the widget actually added to the splitter (not
        # just the inner scroll area) so the panel can never render
        # narrower than this regardless of how the splitter negotiates
        # initial space.
        outer.setMinimumWidth(380)
        outer.setMaximumWidth(520)
        return outer

    def _build_results_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # -- Summary pills + filter row --------------------------------
        top_row = QHBoxLayout()
        self.summary_label = QLabel("No scan run yet.")
        self.summary_label.setObjectName("subheading")
        top_row.addWidget(self.summary_label, stretch=1)

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info"])
        self.severity_filter.currentTextChanged.connect(self._apply_filter)
        top_row.addWidget(self.severity_filter)

        self.text_filter = QLineEdit()
        self.text_filter.setPlaceholderText("Filter by title, file, or rule…")
        self.text_filter.setMaximumWidth(260)
        self.text_filter.textChanged.connect(self._apply_filter)
        top_row.addWidget(self.text_filter)
        layout.addLayout(top_row)

        # -- Findings table --------------------------------------------
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severity", "Title", "Affected", "Module", "Top Location"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self._open_finding_detail)
        layout.addWidget(self.table, stretch=3)

        # -- Log console -----------------------------------------------
        log_label = QLabel("Scan Log")
        log_label.setObjectName("subheading")
        layout.addWidget(log_label)
        self.log_console = QPlainTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setMaximumBlockCount(5000)
        layout.addWidget(self.log_console, stretch=1)

        return panel

    # ------------------------------------------------------------------
    # Settings persistence
    # ------------------------------------------------------------------
    def _load_settings_into_ui(self) -> None:
        if self.settings.last_target:
            self.target_input.setText(self.settings.last_target)
        if self.settings.last_services_file:
            self.services_input.setText(self.settings.last_services_file)
        self.opt_entropy.setChecked(self.settings.enable_entropy)
        self.opt_pestrings.setChecked(self.settings.scan_pe_strings)
        self.opt_osslsigncode.setChecked(self.settings.use_osslsigncode)
        self.opt_include_inventory.setChecked(self.settings.include_inventory)
        selected = set(self.settings.selected_modules)
        for module_id, cb in self._module_checks.items():
            cb.setChecked(module_id in selected)
        if self.settings.vt_api_key:
            self.vt_api_key_input.setPlaceholderText("Saved key in use — paste a new one to replace it")
        self.opt_vt_include_clean.setChecked(self.settings.vt_include_clean)
        self.vt_max_lookups_input.setValue(self.settings.vt_max_lookups)
        self._update_vt_eta_label()

    def _save_settings_from_ui(self) -> None:
        self.settings.last_target = self.target_input.text()
        self.settings.last_services_file = self.services_input.text()
        self.settings.enable_entropy = self.opt_entropy.isChecked()
        self.settings.scan_pe_strings = self.opt_pestrings.isChecked()
        self.settings.use_osslsigncode = self.opt_osslsigncode.isChecked()
        self.settings.include_inventory = self.opt_include_inventory.isChecked()
        self.settings.selected_modules = [m for m, cb in self._module_checks.items() if cb.isChecked()]
        # Only overwrite the saved API key if the analyst actually typed a
        # new one this session — otherwise leave the previously saved key
        # (which we deliberately never echo back into the field) intact.
        typed_key = self.vt_api_key_input.text().strip()
        if typed_key:
            self.settings.vt_api_key = typed_key
            self.vt_api_key_input.clear()
            self.vt_api_key_input.setPlaceholderText("Saved key in use — paste a new one to replace it")
        self.settings.vt_include_clean = self.opt_vt_include_clean.isChecked()
        self.settings.vt_max_lookups = self.vt_max_lookups_input.value()

    def closeEvent(self, event) -> None:
        try:
            self._save_settings_from_ui()
            self.settings.save_geometry(self.saveGeometry())
        except Exception:
            logger.error("Failed to persist settings on close:\n%s", traceback.format_exc())
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Target selection
    # ------------------------------------------------------------------
    def _browse_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select target application folder")
        if path:
            self.target_input.setText(path)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select a single .exe or .dll", "",
            "Windows binaries (*.exe *.dll *.sys *.ocx);;All files (*.*)",
        )
        if path:
            self.target_input.setText(path)

    def _on_target_changed(self) -> None:
        self._update_target_hint()

    def _update_target_hint(self) -> None:
        value = self.target_input.text().strip()
        if not value:
            self.target_hint.setText("")
            return
        p = Path(value)
        looks_like_file = value.lower().endswith(FILE_EXTENSIONS)
        if not p.exists():
            self.target_hint.setText("⚠ This path does not exist.")
            return
        if p.is_file() or looks_like_file:
            self.target_hint.setText(f"Single-file scan — only {p.name} is analyzed.")
        else:
            self.target_hint.setText("Folder scan — every file under this path is analyzed.")

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------
    def _start_scan(self) -> None:
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Target required", "Enter or select a target folder or file first.")
            return

        target_path = Path(target)
        if not target_path.exists():
            QMessageBox.warning(self, "Target not found", f"This path does not exist:\n{target}")
            return

        single_file = None
        target_dir = target_path
        if target_path.is_file():
            single_file = target_path
            target_dir = target_path.parent

        modules = [m for m, cb in self._module_checks.items() if cb.isChecked()]
        if self.opt_reputation.isChecked():
            modules.append("reputation")
        if not modules:
            QMessageBox.warning(self, "No modules selected", "Select at least one module to run.")
            return

        services_file = self.services_input.text().strip()
        if services_file and not Path(services_file).is_file():
            QMessageBox.warning(self, "Services file not found", f"This path does not exist:\n{services_file}")
            return

        if self.opt_reputation.isChecked() and self.opt_vt_upload.isChecked() and not self.opt_vt_upload_confirm.isChecked():
            QMessageBox.warning(
                self, "Confirmation required",
                "Check the upload-confirmation box before running with VirusTotal upload enabled.",
            )
            return

        self._save_settings_from_ui()
        self._reset_run_ui()

        params = {
            "target": target,
            "target_dir": target_dir,
            "single_file": single_file,
            "modules": modules,
            "enable_entropy": self.opt_entropy.isChecked(),
            "scan_pe_strings": self.opt_pestrings.isChecked(),
            "use_osslsigncode": self.opt_osslsigncode.isChecked(),
            "include_inventory": self.opt_include_inventory.isChecked(),
            "services_file": services_file,
            "vt_api_key": self.vt_api_key_input.text().strip() or self.settings.vt_api_key,
            "vt_include_clean": self.opt_vt_include_clean.isChecked(),
            "vt_upload_unknown": self.opt_vt_upload.isChecked(),
            "vt_max_lookups": self.vt_max_lookups_input.value(),
        }

        self.run_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setRange(0, 0)
        self._elapsed_seconds = 0
        self._elapsed_timer.start(1000)

        try:
            self.controller.start(params)
        except Exception as e:
            logger.error("Failed to start scan: %s\n%s", e, traceback.format_exc())
            self._append_log(f"Failed to start scan: {e}", "error")
            self._scan_ui_reset()

    def _update_vt_eta_label(self) -> None:
        # Free-tier VirusTotal is 1 lookup per ~15s — shown as a worst-case
        # estimate right next to the control that determines it, so this
        # time cost is visible before Run Scan is clicked, not discovered
        # 15+ minutes into a scan that already looked "done."
        n = self.vt_max_lookups_input.value()
        seconds = n * 15
        minutes, secs = divmod(seconds, 60)
        eta = f"{minutes}m {secs}s" if minutes else f"{secs}s"
        self.vt_eta_label.setText(
            f"Worst case on the free API tier: up to {eta} added to the scan, checking {n} "
            f"binaries at ~15s each. Runs after all other selected modules finish. A paid "
            f"tier lifts the per-lookup wait — this estimate is free-tier-conservative."
        )

    def _test_vt_key(self) -> None:
        key = self.vt_api_key_input.text().strip() or self.settings.vt_api_key
        if not key:
            self.vt_test_status.setText("No API key to test — paste one first.")
            self.vt_test_status.setStyleSheet(f"color: {theme.get_palette()['AMBER']};")
            return

        self.vt_test_btn.setEnabled(False)
        self.vt_test_btn.setText("Testing… (up to ~20s)")
        self.vt_test_status.setText("")

        self._vt_test_thread = QThread()
        self._vt_test_worker = VTTestWorker(key)
        self._vt_test_worker.moveToThread(self._vt_test_thread)
        self._vt_test_thread.started.connect(self._vt_test_worker.run)
        self._vt_test_worker.result.connect(self._on_vt_test_result)
        self._vt_test_thread.start()

    def _on_vt_test_result(self, ok: bool, message: str) -> None:
        self.vt_test_btn.setEnabled(True)
        self.vt_test_btn.setText("Test Key")
        self.vt_test_status.setText(("✓ " if ok else "✗ ") + message)
        palette = theme.get_palette()
        self.vt_test_status.setStyleSheet(f"color: {palette['GREEN'] if ok else palette['RED']};")
        if self._vt_test_thread:
            self._vt_test_thread.quit()
            self._vt_test_thread.wait(3000)
        self._vt_test_thread = None
        self._vt_test_worker = None

    def _cancel_scan(self) -> None:
        self.cancel_btn.setEnabled(False)
        self.controller.cancel()
        self._append_log("Cancellation requested…", "warn")

    def _reset_run_ui(self) -> None:
        self.table.setRowCount(0)
        self.log_console.clear()
        self.summary_label.setText("Running…")
        self.open_report_btn.setEnabled(False)
        self.export_json_btn.setEnabled(False)
        self._current_result = None

    def _tick_elapsed(self) -> None:
        self._elapsed_seconds += 1
        m, s = divmod(self._elapsed_seconds, 60)
        self.elapsed_label.setText(f"{m}:{s:02d}")

    def _scan_ui_reset(self) -> None:
        self.run_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setRange(0, 100)
        self._elapsed_timer.stop()

    def _on_progress(self, files_scanned: int, current_path: str) -> None:
        self.status_files_label.setText(f"{files_scanned} files scanned")

    def _on_log_line(self, message: str, level: str) -> None:
        self._append_log(message, level)

    def _append_log(self, message: str, level: str) -> None:
        palette = theme.get_palette()
        colors = {"dim": palette["MUTED"], "warn": palette["AMBER"], "error": palette["RED"], "ok": palette["GREEN"]}
        color = colors.get(level, palette["TEXT"])
        ts = datetime.now().strftime("%H:%M:%S")
        # appendHtml() renders its argument as rich text, and log messages
        # routinely embed attacker-controlled data (filenames, paths, raw
        # exception text) pulled straight from the scanned target — escape
        # it the same way the HTML report does, so a crafted filename like
        # `<img src=...>.exe` can't inject markup into the log pane.
        safe_message = html.escape(message)
        self.log_console.appendHtml(
            f'<span style="color:{palette["MUTED"]}">{ts}</span> '
            f'<span style="color:{color}">{safe_message}</span>'
        )

    def _on_finished(self, result) -> None:
        self._scan_ui_reset()
        if result is None:
            self.summary_label.setText("Scan cancelled.")
            return

        self._current_result = result
        self._populate_table(result.findings)
        counts = result.summary_counts()
        self.summary_label.setText(
            "  ·  ".join(f"{k}: {v}" for k, v in counts.items())
        )

        try:
            self._write_reports(result)
            self.open_report_btn.setEnabled(True)
            self.export_json_btn.setEnabled(True)
        except Exception as e:
            logger.error("Failed to write reports: %s\n%s", e, traceback.format_exc())
            self._append_log(f"Failed to write report files: {e}", "error")

    def _on_failed(self, message: str) -> None:
        self._scan_ui_reset()
        self.summary_label.setText("Scan failed.")
        QMessageBox.critical(self, "Scan failed", message)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def _write_reports(self, result) -> None:
        job_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        html_path = REPORTS_DIR / f"warden_report_{job_id}.html"
        json_path = REPORTS_DIR / f"warden_report_{job_id}.json"
        generate_html_report(result, html_path)
        json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        self._current_report_html = html_path
        self._current_report_json = json_path
        self._append_log(f"Report written: {html_path.name}", "ok")

    def _open_report(self) -> None:
        if self._current_report_html and self._current_report_html.exists():
            webbrowser.open(self._current_report_html.as_uri())

    def _export_json(self) -> None:
        if not self._current_report_json or not self._current_report_json.exists():
            return
        dest, _ = QFileDialog.getSaveFileName(
            self, "Export findings as JSON", self._current_report_json.name, "JSON files (*.json)"
        )
        if dest:
            try:
                Path(dest).write_text(self._current_report_json.read_text(encoding="utf-8"), encoding="utf-8")
                self._append_log(f"Exported to {dest}", "ok")
            except OSError as e:
                QMessageBox.warning(self, "Export failed", str(e))

    # ------------------------------------------------------------------
    # Findings table
    # ------------------------------------------------------------------
    def _populate_table(self, findings: list[Finding]) -> None:
        self._last_findings = findings
        grouped = group_findings(findings)
        self.table.setRowCount(0)
        self.table.setRowCount(len(grouped))
        for row, f in enumerate(grouped):
            sev_item = QTableWidgetItem(f["severity"])
            color = QColor(SEVERITY_COLORS.get(f["severity"], "#8b8f96"))
            sev_item.setForeground(color)
            sev_item.setData(Qt.ItemDataRole.UserRole, f)

            title = f["title"]
            affected = int(f.get("affected_count") or len(f.get("locations", [])) or 1)
            if affected > 1:
                title = f"{title} ({affected} locations)"
            title_item = QTableWidgetItem(title)
            affected_item = QTableWidgetItem(str(affected))
            module_item = QTableWidgetItem(f["module"])
            top_location = (f.get("locations") or [f.get("file_path", "")])[0]
            file_item = QTableWidgetItem(top_location)

            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, title_item)
            self.table.setItem(row, 2, affected_item)
            self.table.setItem(row, 3, module_item)
            self.table.setItem(row, 4, file_item)

        self.table.resizeRowsToContents()

    def _apply_filter(self) -> None:
        severity = self.severity_filter.currentText()
        text = self.text_filter.text().strip().lower()
        for row in range(self.table.rowCount()):
            sev_item = self.table.item(row, 0)
            title_item = self.table.item(row, 1)
            file_item = self.table.item(row, 4)
            if sev_item is None:
                continue
            severity_match = severity == "All Severities" or sev_item.text() == severity
            text_match = (
                not text
                or text in title_item.text().lower()
                or text in file_item.text().lower()
            )
            self.table.setRowHidden(row, not (severity_match and text_match))

    def _open_finding_detail(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        sev_item = self.table.item(row, 0)
        finding = sev_item.data(Qt.ItemDataRole.UserRole)
        if finding is None:
            return
        dialog = FindingDialog(finding, parent=self)
        dialog.exec()
