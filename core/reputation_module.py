"""
Module: reputation — cross-checks scanned binaries against VirusTotal.

Opt-in only: requires an explicit API key. Without one, this module simply
produces no findings and logs a single informational note rather than
failing the scan — a missing/unset VT key is a normal, expected state, not
an error condition.

Hash lookup only by default (see core/virustotal_utils.py for why). File
upload is a separate, explicit opt-in (`upload_unknown=True`) that a
caller must deliberately choose.
"""
from __future__ import annotations

from pathlib import Path

from core.fs_walk import find_elf_files, find_macho_files, find_pe_files
from core.models import Finding, Severity
from core.virustotal_utils import VTClient, compute_sha256

MODULE_NAME = "reputation"

# Cap how many binaries get checked per scan so a large target tree can't
# accidentally burn through a whole day's free-tier VT quota (500/day) in
# one run, or make a large scan take hours purely on VT rate-limit waits.
DEFAULT_MAX_LOOKUPS = 40


def _severity_for_verdict(malicious: int, suspicious: int, total_engines: int) -> Severity:
    if total_engines == 0:
        return Severity.INFO
    ratio = malicious / total_engines
    if malicious >= 5 or ratio >= 0.15:
        return Severity.CRITICAL
    if malicious >= 1:
        return Severity.HIGH
    if suspicious >= 1:
        return Severity.MEDIUM
    return Severity.INFO


def run(
    target_dir: str | Path,
    api_key: str | None = None,
    single_file: str | Path | None = None,
    include_clean: bool = False,
    max_lookups: int = DEFAULT_MAX_LOOKUPS,
    upload_unknown: bool = False,
    progress_callback=None,
    error_callback=None,
) -> list[Finding]:
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None
    findings: list[Finding] = []

    if not api_key or not api_key.strip():
        if error_callback:
            error_callback(
                "reputation: no VirusTotal API key configured — skipping reputation checks. "
                "This is expected if you haven't set one up; not a failure."
            )
        return findings

    try:
        client = VTClient(api_key)
    except ValueError as e:
        if error_callback:
            error_callback(f"reputation: {e}")
        return findings

    binaries: list[Path] = []
    binaries.extend(find_pe_files(target_dir, single_file=single_file))
    binaries.extend(find_elf_files(target_dir, single_file=single_file))
    binaries.extend(find_macho_files(target_dir, single_file=single_file))
    # De-dupe (a file could theoretically match more than one finder in
    # edge cases) while preserving order.
    seen_paths = set()
    binaries = [p for p in binaries if not (p in seen_paths or seen_paths.add(p))]

    if not binaries:
        if error_callback:
            error_callback(
                "reputation: no .exe/.dll/.elf/Mach-O binaries found under this target — "
                "nothing for VirusTotal to check."
            )
        return findings

    if len(binaries) > max_lookups and error_callback:
        error_callback(
            f"reputation: {len(binaries)} binaries found, only checking the first {max_lookups} "
            f"to stay within VirusTotal rate/quota limits. Increase max_lookups if you have a "
            f"paid API tier and need full coverage."
        )
    binaries = binaries[:max_lookups]

    if error_callback:
        error_callback(f"reputation: checking {len(binaries)} binary/binaries against VirusTotal "
                        f"(this can take a while on the free tier — 1 lookup every ~15s)...")

    checked = 0
    flagged = 0
    lookup_failed = 0
    unknown = 0

    for binary_path in binaries:
        if progress_callback:
            progress_callback(str(binary_path))

        try:
            sha256 = compute_sha256(binary_path)
        except OSError as e:
            if error_callback:
                error_callback(f"reputation: could not hash '{binary_path}': {e}")
            continue

        verdict = client.lookup_hash(sha256)
        checked += 1

        if verdict.error:
            lookup_failed += 1
            if error_callback:
                error_callback(f"reputation: VirusTotal lookup failed for '{binary_path}': {verdict.error}")
            continue

        if not verdict.found:
            unknown += 1
            if upload_unknown:
                try:
                    verdict = client.upload_file(binary_path)
                except Exception as e:
                    if error_callback:
                        error_callback(f"reputation: upload failed for '{binary_path}': {e}")
                    continue
            elif include_clean:
                findings.append(Finding(
                    module=MODULE_NAME,
                    rule_id="vt-unknown",
                    title="Not previously seen by VirusTotal",
                    severity=Severity.INFO,
                    file_path=str(binary_path),
                    evidence=f"sha256={sha256}",
                    description=(
                        "This binary's hash has no record in VirusTotal's database. This is "
                        "neutral, not reassuring — it just means no scanner has analyzed this "
                        "exact file before (common for freshly built/internal software)."
                    ),
                    confidence="High",
                    tags=["reputation", "virustotal"],
                ))
            else:
                continue

        if verdict.is_flagged:
            flagged += 1
            severity = _severity_for_verdict(verdict.malicious, verdict.suspicious, verdict.total_engines)
            vendor_list = ", ".join(verdict.vendor_flags[:10])
            if len(verdict.vendor_flags) > 10:
                vendor_list += f", +{len(verdict.vendor_flags) - 10} more"
            findings.append(Finding(
                module=MODULE_NAME,
                rule_id="vt-flagged",
                title=f"Flagged by VirusTotal ({verdict.detection_ratio} engines)",
                severity=severity,
                file_path=str(binary_path),
                evidence=f"sha256={sha256}  ·  {verdict.detection_ratio} engines flagged this file",
                description=(
                    f"This exact binary (by SHA-256) has prior detections on VirusTotal. "
                    f"{verdict.malicious} engine(s) flagged it malicious, "
                    f"{verdict.suspicious} flagged it suspicious, out of {verdict.total_engines} total. "
                    f"Flagging vendors: {vendor_list or 'unavailable'}."
                ),
                remediation=(
                    "Confirm this isn't a known false positive for a legitimate packer/installer "
                    "before treating this as conclusive — review the VirusTotal report directly, "
                    "then quarantine and investigate the build/distribution pipeline that produced "
                    "this binary if the detections hold up."
                ),
                poc=f"View the full VirusTotal report: {verdict.permalink}",
                confidence="High" if verdict.malicious >= 3 else "Medium",
                tags=["reputation", "virustotal"],
                extra={"vt_permalink": verdict.permalink, "vt_ratio": verdict.detection_ratio},
            ))
        elif verdict.found and include_clean:
            findings.append(Finding(
                module=MODULE_NAME,
                rule_id="vt-clean",
                title="Clean on VirusTotal",
                severity=Severity.INFO,
                file_path=str(binary_path),
                evidence=f"sha256={sha256}  ·  0/{verdict.total_engines} engines flagged this file",
                description="No VirusTotal engine flagged this exact binary as malicious or suspicious.",
                poc=f"View the full VirusTotal report: {verdict.permalink}",
                confidence="High",
                tags=["reputation", "virustotal"],
                extra={"vt_permalink": verdict.permalink},
            ))

    if error_callback:
        error_callback(
            f"reputation: done — {checked} binary/binaries checked via VirusTotal, "
            f"{flagged} flagged, {unknown} unknown to VT"
            + (f", {lookup_failed} lookup(s) failed" if lookup_failed else "") + "."
        )

    return findings
