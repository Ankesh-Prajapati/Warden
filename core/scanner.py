"""
Warden orchestrator.

Coordinates individual modules and merges their Finding output into a single
scan result. Modules 2-4 are stubbed here and will be wired in as they're
built, one at a time.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core import dll_hijack_module, re_exposure_module, secrets_module, signature_module
from core.models import Finding, ScanMetadata, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ScanResult:
    def __init__(self, metadata: ScanMetadata, findings: list[Finding]):
        self.metadata = metadata
        self.findings = findings

    def summary_counts(self) -> dict:
        """Counts unique vulnerabilities (module+rule+title+severity), not
        one count per affected file — matches how the HTML report groups
        findings, so the summary cards and the finding list agree."""
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        seen = set()
        for f in self.findings:
            key = (f.module, f.rule_id, f.title, f.severity.value)
            if key in seen:
                continue
            seen.add(key)
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "target_path": self.metadata.target_path,
                "started_at": self.metadata.started_at,
                "finished_at": self.metadata.finished_at,
                "files_scanned": self.metadata.files_scanned,
                "tool_version": self.metadata.tool_version,
            },
            "summary": self.summary_counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def run_scan(
    target_dir: str | Path,
    modules: list[str] | None = None,
    rules_dir: str | Path | None = None,
    enable_entropy: bool = True,
    scan_pe_strings: bool = True,
    services_file: str | Path | None = None,
    use_osslsigncode: bool = True,
    progress_callback=None,
    error_callback=None,
) -> ScanResult:
    """
    Run the requested modules against target_dir and return a merged ScanResult.

    modules: list of module names to run. Currently supported: ["secrets"].
             Defaults to all currently-implemented modules.
    """
    if modules is None:
        modules = ["secrets"]

    target_dir = Path(target_dir)
    if not target_dir.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_dir}")

    metadata = ScanMetadata(target_path=str(target_dir))
    all_findings: list[Finding] = []
    files_scanned = {"count": 0}

    def _wrapped_progress(path: str):
        files_scanned["count"] += 1
        if progress_callback:
            progress_callback(path)

    def _run_module(name: str, func, **kwargs) -> list[Finding]:
        try:
            return func(**kwargs)
        except Exception as e:  # keep scanning other modules on a single failure
            if error_callback:
                error_callback(f"{name} module failed and was skipped: {e}")
            return []

    if "secrets" in modules:
        all_findings.extend(_run_module(
            "secrets", secrets_module.run,
            target_dir=target_dir,
            rules_dir=rules_dir,
            enable_entropy=enable_entropy,
            scan_pe_strings=scan_pe_strings,
            progress_callback=_wrapped_progress,
        ))

    if "dll_hijack" in modules:
        all_findings.extend(_run_module(
            "dll_hijack", dll_hijack_module.run,
            target_dir=target_dir,
            services_file=services_file,
            progress_callback=_wrapped_progress,
        ))

    if "signature" in modules:
        all_findings.extend(_run_module(
            "signature", signature_module.run,
            target_dir=target_dir,
            use_osslsigncode=use_osslsigncode,
            progress_callback=_wrapped_progress,
        ))

    if "re_exposure" in modules:
        all_findings.extend(_run_module(
            "re_exposure", re_exposure_module.run,
            target_dir=target_dir,
            progress_callback=_wrapped_progress,
        ))

    metadata.files_scanned = files_scanned["count"]
    metadata.finished_at = datetime.now(timezone.utc).isoformat()

    return ScanResult(metadata, all_findings)
