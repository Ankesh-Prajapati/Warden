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
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
) -> ScanResult:
    """
    Run the requested modules against target_dir and return a merged ScanResult.

    modules: list of module names to run. Currently supported: ["secrets"].
             Defaults to all currently-implemented modules.
    single_file: if given, every module is restricted to analyzing exactly
        this one file (target_dir is still used as directory context, e.g.
        for sibling-DLL inventory in Module 2) instead of walking the whole
        target_dir tree. This is what a "select a single EXE" scan maps to.
    """
    if modules is None:
        modules = ["secrets"]

    target_dir = Path(target_dir)
    if not target_dir.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_dir}")

    single_file = Path(single_file) if single_file else None
    if single_file is not None and not single_file.is_file():
        raise FileNotFoundError(f"single_file target does not exist or is not a file: {single_file}")

    metadata = ScanMetadata(target_path=str(single_file) if single_file else str(target_dir))
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
            single_file=single_file,
            progress_callback=_wrapped_progress,
        ))

    if "dll_hijack" in modules:
        all_findings.extend(_run_module(
            "dll_hijack", dll_hijack_module.run,
            target_dir=target_dir,
            services_file=services_file,
            single_file=single_file,
            progress_callback=_wrapped_progress,
        ))

    if "signature" in modules:
        all_findings.extend(_run_module(
            "signature", signature_module.run,
            target_dir=target_dir,
            use_osslsigncode=use_osslsigncode,
            single_file=single_file,
            progress_callback=_wrapped_progress,
        ))

    if "re_exposure" in modules:
        all_findings.extend(_run_module(
            "re_exposure", re_exposure_module.run,
            target_dir=target_dir,
            single_file=single_file,
            progress_callback=_wrapped_progress,
        ))

    metadata.files_scanned = files_scanned["count"]
    metadata.finished_at = datetime.now(timezone.utc).isoformat()

    return ScanResult(metadata, all_findings)
