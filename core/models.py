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
    evidence: str                     # original extracted evidence
    description: str = ""             # longer explanation of the issue
    remediation: str = ""             # fix guidance
    poc: str = ""                     # detailed proof-of-concept / reproduction steps
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    offset: Optional[int] = None      # byte offset (for binary findings)
    tags: list[str] = field(default_factory=list)
    confidence: str = "Medium"        # Low/Medium/High - reduces FP noise in report
    extra: dict = field(default_factory=dict)  # module-specific structured data

    def fingerprint(self) -> str:
        """Deduplicate repeated emissions, but retain distinct locations and
        distinct evidence. Evidence must be part of the identity: many
        findings have no line/offset (one per unbundled DLL, per service, per
        config key), and without it they all collapsed into the first one."""
        raw = (
            f"{self.module}|{self.rule_id}|{self.file_path}|"
            f"{self.line_number}|{self.column_number}|{self.offset}|{self.evidence}"
        )
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Inverse of to_dict() - used to restore cached findings."""
        return cls(
            module=d["module"],
            rule_id=d["rule_id"],
            title=d["title"],
            severity=Severity.from_str(d["severity"]),
            file_path=d["file_path"],
            evidence=d["evidence"],
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
            poc=d.get("poc", ""),
            line_number=d.get("line_number"),
            column_number=d.get("column_number"),
            offset=d.get("offset"),
            tags=list(d.get("tags", [])),
            confidence=d.get("confidence", "Medium"),
            extra=dict(d.get("extra", {})),
        )

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
            "column_number": self.column_number,
            "offset": self.offset,
            "tags": self.tags,
            "confidence": self.confidence,
            "extra": self.extra,
            "fingerprint": self.fingerprint(),
        }
        return d


@dataclass
class ScanMetadata:
    target_path: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    files_scanned: int = 0
    input_files_scanned: int = 0
    extracted_files_scanned: int = 0
    module_execution_counts: dict[str, int] = field(default_factory=dict)
    module_input_execution_counts: dict[str, int] = field(default_factory=dict)
    module_extracted_execution_counts: dict[str, int] = field(default_factory=dict)
    tool_version: str = "1.3.0"
