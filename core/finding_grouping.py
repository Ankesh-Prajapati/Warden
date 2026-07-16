"""Shared finding grouping for report and desktop UI."""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from core.models import Finding


def group_finding_dicts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    for f in findings:
        key = (f["module"], f["rule_id"], f["title"], f["severity"])
        loc = f["file_path"] + (f" (line {f['line_number']})" if f.get("line_number") else "")
        context = (f.get("extra") or {}).get("context") or ""
        if key not in grouped:
            grouped[key] = deepcopy(f)
            grouped[key]["locations"] = [loc]
            grouped[key]["contexts"] = [context]
            grouped[key]["affected_count"] = 1
            order.append(key)
        else:
            grouped[key]["locations"].append(loc)
            grouped[key]["contexts"].append(context)
            grouped[key]["affected_count"] += 1
    return [grouped[k] for k in order]


def group_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    return group_finding_dicts([f.to_dict() for f in findings])
