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
from desktop import theme
from desktop.theme import SEVERITY_COLORS


def _section(title: str, body: str) -> QWidget:
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)

    heading = QLabel(title)
    heading.setStyleSheet(
        f"font-weight: 700; font-size: 11px; letter-spacing: 0.4px; "
        f"text-transform: uppercase; color: {theme.get_palette()['MUTED']};"
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
        meta.setStyleSheet(f"color: {theme.get_palette()['MUTED']}; font-size: 11.5px;")
        outer.addWidget(meta)

        occurrences = f.get("occurrences") or [f]
        count_label = QLabel(
            f"{len(occurrences)} affected occurrence{'s' if len(occurrences) != 1 else ''}"
        )
        count_label.setTextFormat(Qt.TextFormat.PlainText)
        count_label.setStyleSheet(f"font-family: Consolas, monospace; font-size: 11.5px; color: {theme.get_palette()['ACCENT_SOFT']};")
        count_label.setWordWrap(True)
        outer.addWidget(count_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setSpacing(14)

        body_layout.addWidget(_section("Description", f.get("description", "")))
        occurrence_heading = QLabel("Occurrences")
        occurrence_heading.setStyleSheet(
            f"font-weight: 700; font-size: 11px; color: {theme.get_palette()['MUTED']};"
        )
        body_layout.addWidget(occurrence_heading)
        for index, occurrence in enumerate(occurrences, start=1):
            body_layout.addWidget(self._occurrence_widget(index, occurrence))
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

    def _occurrence_widget(self, index: int, occurrence: dict) -> QWidget:
        palette = theme.get_palette()
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)
        container.setObjectName("findingOccurrence")
        container.setStyleSheet(
            f"QWidget#findingOccurrence {{ border: 1px solid {palette['BORDER']}; border-radius: 6px; }}"
        )

        location = occurrence.get("file_path") or occurrence.get("location", "-")
        metadata = [f"{index}. {location}"]
        if occurrence.get("offset") is not None:
            metadata.append(f"offset 0x{occurrence['offset']:X}")
        elif occurrence.get("line_number"):
            line = f"line {occurrence['line_number']}"
            if occurrence.get("column_number") is not None:
                line += f", column {occurrence['column_number']}"
            metadata.append(line)
        metadata.append(f"confidence {occurrence.get('confidence', 'Medium')}")
        label = QLabel("  |  ".join(metadata))
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        header = QHBoxLayout()
        header.addWidget(label, stretch=1)
        expand = QPushButton("Show details")
        expand.setCheckable(True)
        header.addWidget(expand)
        layout.addLayout(header)

        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(6)
        evidence = QPlainTextEdit(occurrence.get("evidence") or "-")
        evidence.setReadOnly(True)
        evidence.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        evidence.setMinimumHeight(55)
        evidence.setMaximumHeight(150)
        details_layout.addWidget(evidence)

        context = occurrence.get("context") or (occurrence.get("extra") or {}).get("context")
        if context:
            details_layout.addWidget(_section("Code Context", context))
        if occurrence.get("poc"):
            details_layout.addWidget(_section("Proof of Concept", occurrence["poc"]))
        details.hide()

        def set_details_visible(checked: bool) -> None:
            details.setVisible(checked)
            expand.setText("Hide details" if checked else "Show details")

        expand.toggled.connect(set_details_visible)
        layout.addWidget(details)
        return container
