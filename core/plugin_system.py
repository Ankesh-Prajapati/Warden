"""Lightweight extension hooks for future Python and YARA detectors."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from core.models import Finding


def load_python_detectors(plugins_dir: str | Path | None):
    if not plugins_dir:
        return []
    root = Path(plugins_dir)
    if not root.is_dir():
        return []
    detectors = []
    for path in sorted(root.glob("*.py")):
        spec = importlib.util.spec_from_file_location(f"warden_plugin_{path.stem}", path)
        if not spec or not spec.loader:
            continue
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if callable(getattr(module, "scan_file", None)):
                detectors.append(module.scan_file)
        except Exception:
            continue
    return detectors


def run_python_detectors(detectors, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    for detector in detectors:
        try:
            produced = detector(path) or []
            findings.extend([f for f in produced if isinstance(f, Finding)])
        except Exception:
            continue
    return findings


def compile_yara_rules(rules_dir: str | Path | None):
    root = Path(rules_dir) if rules_dir else Path("rules") / "yara"
    if not root.is_dir():
        return None
    try:
        import yara
    except Exception:
        return None
    files = {p.stem: str(p) for p in root.rglob("*") if p.suffix.lower() in {".yar", ".yara"}}
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception:
        return None
