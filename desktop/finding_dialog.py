"""Detail dialog for a single Finding, opened by double-clicking a results row."""
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
    heading.setStyleSheet("font-weight: 700; font-size: 11px; letter-spacing: 0.4px; "
                           "text-transform: uppercase; color: #8b8f96;")
    layout.addWidget(heading)

    text = QPlainTextEdit(body or "—")
    text.setReadOnly(True)
    text.setMinimumHeight(70)
    text.setMaximumHeight(220)
    layout.addWidget(text)
    return box


class FindingDialog(QDialog):
    def __init__(self, finding: Finding, parent=None):
        super().__init__(parent)
        self.setWindowTitle(finding.title)
        self.resize(760, 640)

        outer = QVBoxLayout(self)

        # -- header ---------------------------------------------------
        header = QHBoxLayout()
        sev_color = SEVERITY_COLORS.get(finding.severity.value, "#8b8f96")
        sev_badge = QLabel(finding.severity.value.upper())
        sev_badge.setStyleSheet(
            f"background-color: {sev_color}22; color: {sev_color}; border: 1px solid {sev_color}55; "
            f"border-radius: 10px; padding: 3px 10px; font-weight: 700; font-size: 11px;"
        )
        title_label = QLabel(finding.title)
        # QLabel auto-detects HTML-looking text and renders it as rich
        # text by default. finding.title/file_path can contain data lifted
        # straight from an untrusted scan target (e.g. a crafted filename
        # or embedded string), so force plain text explicitly rather than
        # letting Qt's heuristic decide — otherwise a filename like
        # `<a href="http://evil.example">` would render as a live link.
        title_label.setTextFormat(Qt.TextFormat.PlainText)
        title_label.setStyleSheet("font-size: 15px; font-weight: 700;")
        title_label.setWordWrap(True)
        header.addWidget(sev_badge)
        header.addWidget(title_label, stretch=1)
        outer.addLayout(header)

        meta = QLabel(
            f"Module: {finding.module}  ·  Rule: {finding.rule_id}  ·  Confidence: {finding.confidence}"
        )
        meta.setTextFormat(Qt.TextFormat.PlainText)
        meta.setStyleSheet("color: #8b8f96; font-size: 11.5px;")
        outer.addWidget(meta)

        path_label = QLabel(finding.file_path + (f"  (line {finding.line_number})" if finding.line_number else ""))
        path_label.setTextFormat(Qt.TextFormat.PlainText)
        path_label.setStyleSheet("font-family: Consolas, monospace; font-size: 11.5px; color: #93aaf3;")
        path_label.setWordWrap(True)
        outer.addWidget(path_label)

        # -- scrollable body -------------------------------------------
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setSpacing(14)

        body_layout.addWidget(_section("Description", finding.description))
        body_layout.addWidget(_section("Evidence", finding.evidence))
        if finding.extra.get("context"):
            body_layout.addWidget(_section("Code Context", finding.extra["context"]))
        body_layout.addWidget(_section("Remediation", finding.remediation))
        if finding.poc:
            body_layout.addWidget(_section("Proof of Concept", finding.poc))
        if finding.tags:
            body_layout.addWidget(_section("Tags", ", ".join(finding.tags)))
        body_layout.addStretch()

        scroll.setWidget(body)
        outer.addWidget(scroll, stretch=1)

        # -- footer -----------------------------------------------------
        footer = QHBoxLayout()
        footer.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        footer.addWidget(close_btn)
        outer.addLayout(footer)
