"""
Visual theme for the Warden desktop app.

A single Qt stylesheet (QSS) applied at the application level, plus the
palette constants other widgets (e.g. the findings table's severity
colors) pull from so everything stays visually consistent in one place.
"""
from __future__ import annotations

import base64

BG = "#101113"
PANEL = "#17181b"
PANEL_ALT = "#131416"
BORDER = "#24262a"
TEXT = "#e9eaec"
MUTED = "#8b8f96"
ACCENT = "#6d8cf0"
ACCENT_SOFT = "#93aaf3"
ACCENT_DIM = "#1c2233"
GREEN = "#7fb069"
AMBER = "#d0b352"
RED = "#e0645c"
ORANGE = "#e08a5c"

SEVERITY_COLORS = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": AMBER,
    "Low": ACCENT_SOFT,
    "Info": MUTED,
}

# Qt stylesheets have no equivalent of CSS ::after/content — a checked
# QCheckBox::indicator only ever gets what's drawn via border/background
# unless you give it an explicit `image:`. Embedding a small checkmark SVG
# as a data URI here (Qt QSS does support data: URIs in url()) means the
# checkmark actually renders instead of leaving a blank filled square.
_CHECKMARK_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    b'<path d="M3.2 8.4L6.4 11.6L12.8 4.4" fill="none" stroke="#11131a" '
    b'stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
_CHECKMARK_DATA_URI = "data:image/svg+xml;base64," + base64.b64encode(_CHECKMARK_SVG).decode("ascii")

QSS = f"""
* {{
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}

QMainWindow, QWidget#centralWidget {{
    background-color: {BG};
}}

QWidget {{
    background-color: transparent;
}}

QFrame#card, QGroupBox {{
    background-color: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
}}

QGroupBox {{
    margin-top: 14px;
    padding: 14px 12px 10px 12px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
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
    background-color: #1c1e22;
    border: 1px solid #34373d;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: #262931;
}}
QPushButton:disabled {{
    color: {MUTED};
    background-color: #17181b;
    border-color: {BORDER};
}}

QPushButton#primary {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    color: #11131a;
}}
QPushButton#primary:hover {{
    background-color: {ACCENT_SOFT};
}}
QPushButton#primary:disabled {{
    background-color: #23262f;
    color: {MUTED};
    border-color: {BORDER};
}}

QPushButton#danger {{
    background-color: #211a1a;
    border-color: #4a2c2b;
    color: {RED};
}}
QPushButton#danger:hover {{
    background-color: #2c1f1e;
}}
QPushButton#danger:disabled {{
    color: {MUTED};
    background-color: #17181b;
    border-color: {BORDER};
}}

QCheckBox {{
    spacing: 8px;
    padding: 3px 0;
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
    image: url({_CHECKMARK_DATA_URI});
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
    background: #34373d;
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: #454952;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
}}
QScrollBar::handle:horizontal {{
    background: #34373d;
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
