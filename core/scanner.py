"""
Warden orchestrator.

Coordinates individual modules and merges their Finding output into a single
scan result. Modules 2-4 are stubbed here and will be wired in as they're
built, one at a time.
"""
from __future__ import annotations

import traceback
from datetime import datetime, timezone
from pathlib import Path

from core.cache_utils import ScanCache
from core import dll_hijack_module, linux_module, macos_module, re_exposure_module, reputation_module, secrets_module, signature_module
from core.fs_walk import iter_all_files
from core.logging_config import get_logger
from core.models import Finding, ScanMetadata, Severity
from core.plugin_system import load_python_detectors, run_python_detectors

logger = get_logger("scanner")

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ScanResult:
    def __init__(self, metadata: ScanMetadata, findings: list[Finding], module_errors: list[str] | None = None):
        self.metadata = metadata
        self.findings = findings
        # Non-fatal problems encountered during the scan (a module crashed,
        # a file was unreadable, etc). The scan still completes and returns
        # every finding collected up to that point — this list is purely
        # for analyst visibility / audit trail, never for aborting the run.
        self.module_errors = module_errors or []

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
            "module_errors": self.module_errors,
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
    vt_api_key: str | None = None,
    vt_include_clean: bool = False,
    vt_max_lookups: int = 40,
    vt_upload_unknown: bool = False,
    progress_callback=None,
    error_callback=None,
    incremental: bool = False,
    cache_file: str | Path | None = None,
    yara_rules_dir: str | Path | None = None,
    plugins_dir: str | Path | None = None,
    max_workers: int = 1,
    include_inventory: bool = True,
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
    module_errors: list[str] = []
    files_scanned = {"count": 0}
    scan_cache = ScanCache(target_dir, enabled=incremental, cache_file=cache_file)

    def _wrapped_progress(path: str):
        files_scanned["count"] += 1
        if progress_callback:
            progress_callback(path)

    def _wrapped_error(message: str):
        module_errors.append(message)
        logger.warning(message)
        if error_callback:
            error_callback(message)

    def _run_module(name: str, func, **kwargs) -> list[Finding]:
        started = datetime.now(timezone.utc)
        try:
            logger.info("Starting module: %s", name)
            result = func(error_callback=_wrapped_error, **kwargs)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            logger.info("Module %s finished in %.2fs with %d finding(s)", name, elapsed, len(result))
            return result
        except Exception as e:  # keep scanning other modules on a single failure
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            logger.error("Module %s failed after %.2fs: %s\n%s", name, elapsed, e, traceback.format_exc())
            _wrapped_error(f"{name} module failed and was skipped: {e}")
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
            scan_cache=scan_cache,
            max_workers=max_workers,
        ))

    if "dll_hijack" in modules:
        all_findings.extend(_run_module(
            "dll_hijack", dll_hijack_module.run,
            target_dir=target_dir,
            services_file=services_file,
            single_file=single_file,
            progress_callback=_wrapped_progress,
        ))

    if plugins_dir:
        detectors = load_python_detectors(plugins_dir)
        if detectors:
            for path in iter_all_files(target_dir, single_file=single_file):
                try:
                    all_findings.extend(run_python_detectors(detectors, path))
                except Exception as e:
                    _wrapped_error(f"plugin: skipped '{path}' after error: {e}")

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
            yara_rules_dir=yara_rules_dir,
            scan_cache=scan_cache,
        ))

    if "linux" in modules:
        all_findings.extend(_run_module(
            "linux", linux_module.run,
            target_dir=target_dir,
            rules_dir=rules_dir,
            enable_entropy=enable_entropy,
            single_file=single_file,
            progress_callback=_wrapped_progress,
            include_inventory=include_inventory,
        ))

    if "macos" in modules:
        all_findings.extend(_run_module(
            "macos", macos_module.run,
            target_dir=target_dir,
            rules_dir=rules_dir,
            enable_entropy=enable_entropy,
            single_file=single_file,
            progress_callback=_wrapped_progress,
            include_inventory=include_inventory,
        ))

    if "reputation" in modules:
        all_findings.extend(_run_module(
            "reputation", reputation_module.run,
            target_dir=target_dir,
            api_key=vt_api_key,
            single_file=single_file,
            include_clean=vt_include_clean,
            max_lookups=vt_max_lookups,
            upload_unknown=vt_upload_unknown,
            progress_callback=_wrapped_progress,
        ))

    metadata.files_scanned = files_scanned["count"]
    metadata.finished_at = datetime.now(timezone.utc).isoformat()
    scan_cache.save()

    return ScanResult(metadata, all_findings, module_errors)
