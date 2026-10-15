"""Shared finding grouping for report and desktop UI."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any

from core.models import Finding
from core.path_utils import normalize_finding_path


def _occurrence_identity(finding: dict[str, Any], normalized_path: str) -> tuple:
    evidence = str(
        finding.get("_identity_evidence")
        or finding.get("evidence")
        or ""
    )
    evidence_digest = hashlib.sha256(evidence.encode("utf-8", errors="replace")).digest()
    return (
        finding["module"],
        finding["rule_id"],
        normalized_path.casefold(),
        finding.get("line_number"),
        finding.get("column_number"),
        finding.get("offset"),
        evidence_digest,
    )


def group_finding_dicts(
    findings: list[dict[str, Any]],
    scan_root: str | None = None,
) -> list[dict[str, Any]]:
    """Group findings by issue while retaining unique, traceable occurrences."""
    grouped: dict[tuple, dict[str, Any]] = {}
    seen_occurrences: dict[tuple, set[tuple]] = {}
    order: list[tuple] = []
    for f in findings:
        normalized_path = normalize_finding_path(
            str(f["file_path"]),
            scan_root,
            (f.get("extra") or {}).get("extracted_from"),
        )
        issue_key = (
            f["module"],
            f["rule_id"],
            f["title"].strip().casefold(),
            f["severity"],
        )
        identity = _occurrence_identity(f, normalized_path)
        occurrence = deepcopy(f)
        occurrence.pop("_identity_evidence", None)
        occurrence["file_path"] = normalized_path
        original_path = str(f["file_path"])
        occurrence["poc"] = str(f.get("poc") or "").replace(original_path, normalized_path)
        occurrence["extra"] = deepcopy(f.get("extra") or {})
        if occurrence["extra"].get("extracted_from"):
            occurrence["extra"]["extracted_from"] = normalize_finding_path(
                str(occurrence["extra"]["extracted_from"]), scan_root
            )
        occurrence["location"] = normalized_path
        if occurrence.get("offset") is not None:
            occurrence["location"] += f" (offset 0x{occurrence['offset']:X})"
        elif occurrence.get("line_number"):
            occurrence["location"] += f" (line {occurrence['line_number']}"
            if occurrence.get("column_number") is not None:
                occurrence["location"] += f", column {occurrence['column_number']}"
            occurrence["location"] += ")"
        occurrence["context"] = (f.get("extra") or {}).get("context") or ""

        if issue_key not in grouped:
            issue = deepcopy(f)
            issue["file_path"] = normalized_path
            issue["locations"] = []
            issue["contexts"] = []
            issue["occurrences"] = []
            issue["affected_count"] = 0
            issue.pop("_identity_evidence", None)
            grouped[issue_key] = issue
            seen_occurrences[issue_key] = set()
            order.append(issue_key)

        issue = grouped[issue_key]
        if identity in seen_occurrences[issue_key]:
            continue
        seen_occurrences[issue_key].add(identity)
        issue["occurrences"].append(occurrence)
        issue["locations"].append(occurrence["location"])
        issue["contexts"].append(occurrence["context"])
        issue["affected_count"] += 1

    for issue in grouped.values():
        first = issue["occurrences"][0]
        issue["file_path"] = first["file_path"]
        issue["evidence"] = first["evidence"]
        issue["confidence"] = first.get("confidence", issue.get("confidence"))
        issue["poc"] = first.get("poc", "")
        issue["extra"] = first.get("extra", {})
    return [grouped[key] for key in order]


def group_findings(
    findings: list[Finding],
    scan_root: str | None = None,
) -> list[dict[str, Any]]:
    """Group in-memory findings while retaining complete occurrence evidence."""
    data = []
    for finding in findings:
        item = finding.to_dict()
        item["_identity_evidence"] = finding.evidence
        data.append(item)
    return group_finding_dicts(
        data,
        scan_root=scan_root,
    )
