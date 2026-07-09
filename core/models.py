"""
Shared data models for Warden findings.

Every module (secrets, dll_hijack, signature, re_exposure) emits Finding
objects through this common schema so the report layer can render them
consistently regardless of which module produced them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls(value.strip().capitalize())
        except ValueError:
            return cls.INFO


@dataclass
class Finding:
    """A single security finding, module-agnostic."""

    module: str                       # e.g. "secrets", "dll_hijack"
    rule_id: str                      # e.g. "aws-access-key-id"
    title: str                        # short human title
    severity: Severity
    file_path: str                    # path to the file the finding came from
    evidence: str                     # evidence snippet (full value, local report only)
    description: str = ""             # longer explanation of the issue
    remediation: str = ""             # fix guidance
    poc: str = ""                     # detailed proof-of-concept / reproduction steps
    line_number: Optional[int] = None
    offset: Optional[int] = None      # byte offset (for binary findings)
    tags: list[str] = field(default_factory=list)
    confidence: str = "Medium"        # Low/Medium/High - reduces FP noise in report
    extra: dict = field(default_factory=dict)  # module-specific structured data

    def fingerprint(self) -> str:
        """Stable dedup key: same rule + file + evidence shouldn't double-count."""
        raw = f"{self.module}|{self.rule_id}|{self.file_path}|{self.evidence}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = {
            "module": self.module,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "poc": self.poc,
            "line_number": self.line_number,
            "offset": self.offset,
            "tags": self.tags,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint(),
        }
        return d


@dataclass
class ScanMetadata:
    target_path: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    files_scanned: int = 0
    tool_version: str = "0.1.0"


def redact(value: str, keep: int = 4) -> str:
    """Redact a secret for safe display in reports: keep first/last `keep` chars."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"
