"""Detail dialog for a single or grouped Finding."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core.models import Finding
from desktop.theme import SEVERITY_COLORS


def _section(title: str, body: str) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)

    heading = QLabel(title)
    heading.setStyleSheet(
        "font-weight: 700; font-size: 11px; letter-spacing: 0.4px; "
        "text-transform: uppercase; color: #8b8f96;"
    )
    layout.addWidget(heading)

    text = QPlainTextEdit(body or "-")
    text.setReadOnly(True)
    text.setMinimumHeight(70)
    text.setMaximumHeight(240)
    layout.addWidget(text)
    return box


class FindingDialog(QDialog):
    def __init__(self, finding: Finding | dict, parent=None):
        super().__init__(parent)
        f = finding.to_dict() if isinstance(finding, Finding) else finding
        self.setWindowTitle(f["title"])
        self.resize(780, 660)

        outer = QVBoxLayout(self)

        header = QHBoxLayout()
        sev_color = SEVERITY_COLORS.get(f["severity"], "#8b8f96")
        sev_badge = QLabel(f["severity"].upper())
        sev_badge.setStyleSheet(
            f"background-color: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}55; "
            f"border-radius: 10px; padding: 3px 10px; font-weight: 700; font-size: 11px;"
        )
        title_label = QLabel(f["title"])
        title_label.setTextFormat(Qt.TextFormat.PlainText)
        title_label.setStyleSheet("font-size: 15px; font-weight: 700;")
        title_label.setWordWrap(True)
        header.addWidget(sev_badge)
        header.addWidget(title_label, stretch=1)
        outer.addLayout(header)

        meta = QLabel(
            f"Module: {f['module']}  |  Rule: {f['rule_id']}  |  Confidence: {f.get('confidence', 'Medium')}"
        )
        meta.setTextFormat(Qt.TextFormat.PlainText)
        meta.setStyleSheet("color: #8b8f96; font-size: 11.5px;")
        outer.addWidget(meta)

        locations = f.get("locations") or [
            f["file_path"] + (f"  (line {f['line_number']})" if f.get("line_number") else "")
        ]
        count_label = QLabel(f"{len(locations)} affected location{'s' if len(locations) != 1 else ''}")
        count_label.setTextFormat(Qt.TextFormat.PlainText)
        count_label.setStyleSheet("font-family: Consolas, monospace; font-size: 11.5px; color: #93aaf3;")
        count_label.setWordWrap(True)
        outer.addWidget(count_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setSpacing(14)

        body_layout.addWidget(_section("Description", f.get("description", "")))
        body_layout.addWidget(_section("Affected Locations", "\n".join(locations)))
        body_layout.addWidget(_section("Evidence", f.get("evidence", "")))
        contexts = [c for c in f.get("contexts", []) if c]
        if not contexts and f.get("extra", {}).get("context"):
            contexts = [f["extra"]["context"]]
        if contexts:
            body_layout.addWidget(_section("Code Context", "\n\n---\n\n".join(contexts[:10])))
        body_layout.addWidget(_section("Remediation", f.get("remediation", "")))
        if f.get("poc"):
            body_layout.addWidget(_section("Proof of Concept", f["poc"]))
        if f.get("tags"):
            body_layout.addWidget(_section("Tags", ", ".join(f["tags"])))
        body_layout.addStretch()

        scroll.setWidget(body)
        outer.addWidget(scroll, stretch=1)

        footer = QHBoxLayout()
        footer.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        outer.addLayout(footer)
