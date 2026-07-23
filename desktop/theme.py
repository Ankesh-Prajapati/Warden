"""
Visual theme for the Warden desktop app.

Two Qt stylesheets (QSS) — dark (default) and light — built from named
palettes, plus the palette constants other widgets (e.g. the findings
table's severity colors) pull from so everything stays visually
consistent in one place. Switching themes at runtime re-renders the QSS
from the same template with a different palette rather than maintaining
two separate stylesheets by hand.
"""
from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor, QPalette

# Qt stylesheets have no equivalent of CSS ::after/content — a checked
# QCheckBox::indicator only ever gets what's drawn via border/background
# unless you give it an explicit `image:`. A base64 data: URI in url() was
# tried first but proved unreliable in practice (renders inconsistently
# across Qt versions/platforms) — a real file path is the documented,
# reliably-working approach, so the checkmark ships as an actual PNG
# asset instead.
_CHECK_PNG_PATH = (Path(__file__).resolve().parent / "assets" / "check.png").as_posix()

DARK_PALETTE = {
    "BG": "#101113",
    "PANEL": "#17181b",
    "PANEL_ALT": "#131416",
    "BORDER": "#24262a",
    "TEXT": "#e9eaec",
    "MUTED": "#8b8f96",
    "ACCENT": "#6d8cf0",
    "ACCENT_SOFT": "#93aaf3",
    "ACCENT_DIM": "#1c2233",
    "GREEN": "#7fb069",
    "AMBER": "#d0b352",
    "RED": "#e0645c",
    "ORANGE": "#e08a5c",
    "ON_ACCENT_TEXT": "#11131a",
    "BTN_BG": "#1c1e22",
    "BTN_BORDER": "#34373d",
    "BTN_HOVER_BG": "#262931",
    "PRIMARY_DISABLED_BG": "#23262f",
    "DANGER_BG": "#211a1a",
    "DANGER_BORDER": "#4a2c2b",
    "DANGER_HOVER_BG": "#2c1f1e",
    "SCROLLBAR_HANDLE": "#34373d",
    "SCROLLBAR_HANDLE_HOVER": "#454952",
}

# A light enterprise palette — not simply DARK_PALETTE with colors flipped,
# since a naive invert produces washed-out, low-contrast UI chrome. Accent
# is deepened for AA contrast against white, and severity colors are
# individually darkened/saturated where the dark-theme value (tuned for a
# near-black background) would be too pale to read on white.
LIGHT_PALETTE = {
    "BG": "#f4f5f7",
    "PANEL": "#ffffff",
    "PANEL_ALT": "#eef0f3",
    "BORDER": "#d7dbe1",
    "TEXT": "#1b1d21",
    "MUTED": "#666c78",
    "ACCENT": "#3a5bd9",
    "ACCENT_SOFT": "#5470e0",
    "ACCENT_DIM": "#e4e9fc",
    "GREEN": "#2f8f4e",
    "AMBER": "#a5760a",
    "RED": "#c9382f",
    "ORANGE": "#c1650f",
    "ON_ACCENT_TEXT": "#ffffff",
    "BTN_BG": "#f0f1f4",
    "BTN_BORDER": "#c9ced6",
    "BTN_HOVER_BG": "#e4e7ec",
    "PRIMARY_DISABLED_BG": "#dde1e8",
    "DANGER_BG": "#fbeceb",
    "DANGER_BORDER": "#eec4c0",
    "DANGER_HOVER_BG": "#f6dcda",
    "SCROLLBAR_HANDLE": "#c3c8d0",
    "SCROLLBAR_HANDLE_HOVER": "#a9afba",
}

_PALETTES = {"dark": DARK_PALETTE, "light": LIGHT_PALETTE}

_current_mode = "dark"

_QSS_TEMPLATE = """
* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}

QMainWindow, QWidget#centralWidget {{
    background-color: {BG};
}}

QMenuBar {{
    background-color: {PANEL};
    color: {TEXT};
    border-bottom: 1px solid {BORDER};
    padding: 2px 4px;
}}
QMenuBar::item {{
    background: transparent;
    color: {TEXT};
    padding: 5px 12px;
    border-radius: 4px;
}}
QMenuBar::item:selected, QMenuBar::item:pressed {{
    background-color: {ACCENT_DIM};
    color: {TEXT};
}}
QMenu {{
    background-color: {PANEL};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 24px 6px 14px;
    border-radius: 4px;
    color: {TEXT};
}}
QMenu::item:selected {{
    background-color: {ACCENT_DIM};
    color: {TEXT};
}}
QMenu::item:disabled {{
    color: {MUTED};
}}
QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 4px 8px;
}}

QWidget {{
    background-color: transparent;
}}

QDialog, QMessageBox {{
    background-color: {BG};
}}

QFrame#card, QGroupBox {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}

QGroupBox {{
    margin-top: 8px;
    padding: 34px 14px 14px 14px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 14px;
    top: 8px;
    padding: 0;
    color: {ACCENT_SOFT};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.4px;
    text-transform: uppercase;
}}

QLabel#heading {{
    font-size: 16px;
    font-weight: 700;
}}
QLabel#subheading {{
    color: {MUTED};
    font-size: 11.5px;
}}
QLabel.caption {{
    color: {MUTED};
    font-size: 11px;
}}

QLineEdit, QPlainTextEdit, QTextEdit {{
    background-color: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 9px;
    selection-background-color: {ACCENT};
    font-family: "Consolas", "SFMono-Regular", monospace;
    font-size: 12px;
}}
QLineEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {ACCENT};
}}

QPushButton {{
    background-color: {BTN_BG};
    border: 1px solid {BTN_BORDER};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {BTN_HOVER_BG};
}}
QPushButton:disabled {{
    color: {MUTED};
    background-color: {PANEL};
    border-color: {BORDER};
}}

QPushButton#primary {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    color: {ON_ACCENT_TEXT};
}}
QPushButton#primary:hover {{
    background-color: {ACCENT_SOFT};
}}
QPushButton#primary:disabled {{
    background-color: {PRIMARY_DISABLED_BG};
    color: {MUTED};
    border-color: {BORDER};
}}

QPushButton#danger {{
    background-color: {DANGER_BG};
    border-color: {DANGER_BORDER};
    color: {RED};
}}
QPushButton#danger:hover {{
    background-color: {DANGER_HOVER_BG};
}}
QPushButton#danger:disabled {{
    color: {MUTED};
    background-color: {PANEL};
    border-color: {BORDER};
}}

QWidget#dangerBox {{
    border: 1px solid {DANGER_BORDER};
    background-color: {DANGER_BG};
    border-radius: 8px;
}}
QWidget#dangerBox QLabel#dangerWarningText {{
    color: {AMBER};
    font-size: 11px;
}}

QCheckBox {{
    spacing: 8px;
    padding: 3px 0;
}}
QCheckBox:disabled {{
    color: {MUTED};
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {BORDER};
    background: {PANEL_ALT};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    image: url("{_CHECK_PNG_PATH}");
}}

QTableWidget {{
    background-color: {PANEL_ALT};
    alternate-background-color: {PANEL};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    border-radius: 8px;
    selection-background-color: {ACCENT_DIM};
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background-color: {PANEL};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 8px;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
}}
QTableWidget::item {{
    padding: 6px;
}}

QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    top: -1px;
}}
QTabBar::tab {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 7px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    color: {MUTED};
}}
QTabBar::tab:selected {{
    background: {PANEL_ALT};
    color: {TEXT};
}}

QProgressBar {{
    background-color: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 5px;
    height: 9px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 5px;
}}

QStatusBar {{
    background-color: {PANEL_ALT};
    border-top: 1px solid {BORDER};
    color: {MUTED};
    font-size: 11.5px;
}}

QToolBar {{
    background-color: {PANEL_ALT};
    border-bottom: 1px solid {BORDER};
    padding: 6px 10px;
    spacing: 8px;
}}

QSplitter::handle {{
    background-color: {BORDER};
}}

QScrollBar:vertical {{
    background: transparent;
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {SCROLLBAR_HANDLE};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {SCROLLBAR_HANDLE_HOVER};
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: {SCROLLBAR_HANDLE};
    border-radius: 5px;
    min-width: 24px;
}}

QComboBox {{
    background-color: {PANEL_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 10px;
}}
QComboBox QAbstractItemView {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT_DIM};
}}

QToolTip {{
    background-color: {PANEL};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 4px 8px;
}}
"""


def get_palette(mode: str | None = None) -> dict:
    """Returns the active palette dict (current theme if mode is omitted) —
    lets other widgets (scan log, status labels) pull live colors instead
    of hardcoding dark-theme-only hex values that break under the light
    theme."""
    return dict(_PALETTES.get(mode or _current_mode, DARK_PALETTE))


def build_qss(mode: str) -> str:
    """Render the QSS template with the given palette ("dark" or "light")."""
    palette = _PALETTES.get(mode, DARK_PALETTE)
    return _QSS_TEMPLATE.format(_CHECK_PNG_PATH=_CHECK_PNG_PATH, **palette)


def build_qpalette(mode: str) -> QPalette:
    """Build a Qt palette so native-painted widgets match the active theme."""
    p = _PALETTES.get(mode, DARK_PALETTE)
    palette = QPalette()

    window = QColor(p["BG"])
    panel = QColor(p["PANEL"])
    panel_alt = QColor(p["PANEL_ALT"])
    text = QColor(p["TEXT"])
    muted = QColor(p["MUTED"])
    accent = QColor(p["ACCENT"])
    accent_dim = QColor(p["ACCENT_DIM"])

    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, panel_alt)
    palette.setColor(QPalette.ColorRole.AlternateBase, panel)
    palette.setColor(QPalette.ColorRole.ToolTipBase, panel)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, panel)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, QColor(p["RED"]))
    palette.setColor(QPalette.ColorRole.Highlight, accent)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(p["ON_ACCENT_TEXT"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, muted)

    for group in (QPalette.ColorGroup.Disabled, QPalette.ColorGroup.Inactive):
        palette.setColor(group, QPalette.ColorRole.WindowText, muted)
        palette.setColor(group, QPalette.ColorRole.Text, muted)
        palette.setColor(group, QPalette.ColorRole.ButtonText, muted)
        palette.setColor(group, QPalette.ColorRole.Highlight, accent_dim)
        palette.setColor(group, QPalette.ColorRole.HighlightedText, text)

    return palette


def get_severity_colors(mode: str) -> dict:
    p = _PALETTES.get(mode, DARK_PALETTE)
    return {
        "Critical": p["RED"],
        "High": p["ORANGE"],
        "Medium": p["AMBER"],
        "Low": p["ACCENT_SOFT"],
        "Info": p["MUTED"],
    }


def set_theme(mode: str) -> str:
    """
    Switch the active theme at runtime. Mutates the module-level QSS and
    SEVERITY_COLORS *in place* (rather than rebinding the names) so
    existing `from desktop.theme import SEVERITY_COLORS` references in
    finding_dialog.py/main_window.py — which bind to this dict object at
    import time — automatically see the new colors without every call
    site needing to be theme-aware itself. Returns the new QSS string for
    the caller to apply via QApplication.setStyleSheet().
    """
    global _current_mode, QSS
    mode = mode if mode in _PALETTES else "dark"
    _current_mode = mode
    QSS = build_qss(mode)
    SEVERITY_COLORS.clear()
    SEVERITY_COLORS.update(get_severity_colors(mode))
    return QSS


def current_theme() -> str:
    return _current_mode


# Module-level defaults so existing `from desktop.theme import QSS` /
# `SEVERITY_COLORS` call sites keep working unchanged at import time.
QSS = build_qss(_current_mode)
SEVERITY_COLORS = get_severity_colors(_current_mode)
