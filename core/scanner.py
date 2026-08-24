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
from core.archive_extractor import ARCHIVE_EXTENSIONS, cleanup as cleanup_extraction, extract_archive_recursive
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
    vt_max_lookups: int = 15,
    vt_upload_unknown: bool = False,
    progress_callback=None,
    error_callback=None,
    incremental: bool = False,
    cache_file: str | Path | None = None,
    yara_rules_dir: str | Path | None = None,
    plugins_dir: str | Path | None = None,
    max_workers: int = 1,
    include_inventory: bool = True,
    extract_archives: bool = True,
    archive_max_depth: int = 2,
    archive_max_size_mb: int = 500,
    archive_max_candidates: int = 25,
) -> ScanResult:
    """
    Run the requested modules against target_dir and return a merged ScanResult.

    modules: list of module names to run. Currently supported: ["secrets"].
             Defaults to all currently-implemented modules.
    single_file: if given, every module is restricted to analyzing exactly
        this one file (target_dir is still used as directory context, e.g.
        for sibling-DLL inventory in Module 2) instead of walking the whole
        target_dir tree. This is what a "select a single EXE" scan maps to.
    extract_archives: if True (default), installer/archive-looking files
        (NSIS/InnoSetup/MSI/self-extracting installers, ZIP/CAB/7z, and
        plain PEs that happen to carry a nested archive in a resource —
        a real case found during development: a signed installer whose
        PE resources contained a Cabinet archive with five bundled DLLs,
        invisible to every other module) are unpacked with the system
        `7z` binary and their contents scanned too, recursively up to
        archive_max_depth levels. Silently does nothing if `7z` isn't on
        PATH — never a hard failure. Findings from extracted content
        carry extra["extracted_from"] noting the original archive.
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

    def _dispatch_modules(t_dir: Path, s_file: Path | None) -> list[Finding]:
        """Runs every requested module against (t_dir, s_file) and returns
        its findings. Pulled out into its own function so the exact same
        dispatch logic can run a second time against extracted archive
        content, instead of duplicating each `if "x" in modules:` block."""
        findings: list[Finding] = []

        if "secrets" in modules:
            findings.extend(_run_module(
                "secrets", secrets_module.run,
                target_dir=t_dir,
                rules_dir=rules_dir,
                enable_entropy=enable_entropy,
                scan_pe_strings=scan_pe_strings,
                single_file=s_file,
                progress_callback=_wrapped_progress,
                scan_cache=scan_cache,
                max_workers=max_workers,
            ))

        if "dll_hijack" in modules:
            findings.extend(_run_module(
                "dll_hijack", dll_hijack_module.run,
                target_dir=t_dir,
                services_file=services_file,
                single_file=s_file,
                progress_callback=_wrapped_progress,
            ))

        if plugins_dir:
            detectors = load_python_detectors(plugins_dir)
            if detectors:
                for path in iter_all_files(t_dir, single_file=s_file):
                    try:
                        findings.extend(run_python_detectors(detectors, path))
                    except Exception as e:
                        _wrapped_error(f"plugin: skipped '{path}' after error: {e}")

        if "signature" in modules:
            findings.extend(_run_module(
                "signature", signature_module.run,
                target_dir=t_dir,
                use_osslsigncode=use_osslsigncode,
                single_file=s_file,
                progress_callback=_wrapped_progress,
            ))

        if "re_exposure" in modules:
            findings.extend(_run_module(
                "re_exposure", re_exposure_module.run,
                target_dir=t_dir,
                single_file=s_file,
                progress_callback=_wrapped_progress,
                yara_rules_dir=yara_rules_dir,
                scan_cache=scan_cache,
            ))

        if "linux" in modules:
            findings.extend(_run_module(
                "linux", linux_module.run,
                target_dir=t_dir,
                rules_dir=rules_dir,
                enable_entropy=enable_entropy,
                single_file=s_file,
                progress_callback=_wrapped_progress,
                include_inventory=include_inventory,
            ))

        if "macos" in modules:
            findings.extend(_run_module(
                "macos", macos_module.run,
                target_dir=t_dir,
                rules_dir=rules_dir,
                enable_entropy=enable_entropy,
                single_file=s_file,
                progress_callback=_wrapped_progress,
                include_inventory=include_inventory,
            ))

        if "reputation" in modules:
            findings.extend(_run_module(
                "reputation", reputation_module.run,
                target_dir=t_dir,
                api_key=vt_api_key,
                single_file=s_file,
                include_clean=vt_include_clean,
                max_lookups=vt_max_lookups,
                upload_unknown=vt_upload_unknown,
                progress_callback=_wrapped_progress,
            ))

        return findings

    all_findings.extend(_dispatch_modules(target_dir, single_file))

    # --- Archive/installer extraction: unpack and recursively scan any
    # bundled payload (NSIS/InnoSetup/MSI/self-extracting installers,
    # ZIP/CAB/7z, or a plain PE that happens to carry a nested archive in
    # a resource) that the primary pass above never looks inside. ---
    if extract_archives:
        if single_file is not None:
            candidates = [single_file] if single_file.suffix.lower() in ARCHIVE_EXTENSIONS else []
        else:
            candidates = [
                p for p in iter_all_files(target_dir, single_file=None)
                if p.suffix.lower() in ARCHIVE_EXTENSIONS
            ][:archive_max_candidates]

        for candidate in candidates:
            extraction = extract_archive_recursive(
                candidate,
                max_depth=archive_max_depth,
                max_total_bytes=archive_max_size_mb * 1024 * 1024,
            )
            for warning in extraction.warnings:
                _wrapped_error(f"archive extraction ({candidate.name}): {warning}")
            if extraction.root and extraction.extracted_files:
                nested_findings = _dispatch_modules(extraction.root, None)
                for f in nested_findings:
                    f.extra["extracted_from"] = str(candidate)
                    f.tags = list(set(f.tags + ["extracted-content"]))
                all_findings.extend(nested_findings)
            cleanup_extraction(extraction)

    metadata.files_scanned = files_scanned["count"]
    metadata.finished_at = datetime.now(timezone.utc).isoformat()
    scan_cache.save()

    return ScanResult(metadata, all_findings, module_errors)
