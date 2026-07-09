"""
Rule pack loading for the secrets detection engine.

Rules are stored as YAML (gitleaks-style) so users can extend detection
patterns without touching code. See rules/secrets_patterns.yaml for the
default pack and format reference.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from core.models import Severity


@dataclass
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    severity: Severity
    tags: list[str]
    raw_regex: str

    def finditer(self, text: str):
        return self.pattern.finditer(text)


class RuleLoadError(Exception):
    pass


def load_rules_from_file(path: Path) -> list[Rule]:
    """Load and compile rules from a single YAML rule-pack file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules_raw = data.get("rules", [])
    rules: list[Rule] = []
    errors: list[str] = []

    for entry in rules_raw:
        try:
            rule_id = entry["id"]
            regex_str = entry["regex"]
            compiled = re.compile(regex_str)
            rules.append(
                Rule(
                    id=rule_id,
                    description=entry.get("description", rule_id),
                    pattern=compiled,
                    severity=Severity.from_str(entry.get("severity", "Medium")),
                    tags=entry.get("tags", []),
                    raw_regex=regex_str,
                )
            )
        except re.error as e:
            errors.append(f"Rule '{entry.get('id', '?')}' has invalid regex: {e}")
        except KeyError as e:
            errors.append(f"Rule missing required field {e} in {path.name}")

    if errors:
        # Non-fatal: skip bad rules but surface the problem so a broken
        # community-contributed rule pack doesn't silently disable itself.
        for err in errors:
            print(f"[rules] WARNING: {err}")

    return rules


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    """
    Load all rule packs from a directory (default: bundled rules/ dir).

    Any *.yaml or *.yml file in the directory is treated as a rule pack,
    so users can drop in additional packs alongside the default one.
    """
    if rules_dir is None:
        rules_dir = Path(__file__).resolve().parent.parent / "rules"

    rules_dir = Path(rules_dir)
    if not rules_dir.exists():
        raise RuleLoadError(f"Rules directory not found: {rules_dir}")

    all_rules: list[Rule] = []
    seen_ids: set[str] = set()

    for path in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        for rule in load_rules_from_file(path):
            if rule.id in seen_ids:
                print(f"[rules] WARNING: duplicate rule id '{rule.id}' in {path.name}, skipping")
                continue
            seen_ids.add(rule.id)
            all_rules.append(rule)

    if not all_rules:
        raise RuleLoadError(f"No valid rules loaded from {rules_dir}")

    return all_rules
