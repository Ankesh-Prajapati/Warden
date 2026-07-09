"""
Module 1 — Secrets & Config Exposure Scanner.

Scans a target directory tree for:
  - Hardcoded secrets/credentials in text/config files (regex + entropy)
  - Hardcoded secrets embedded as strings inside PE binaries (.exe/.dll)
  - Plaintext credential storage indicators in config/registry-export files
  - Overly permissive file permissions on files containing sensitive data

Emits a flat list of core.models.Finding objects, which the orchestrator
(scanner.py) merges with output from the other modules.
"""
from __future__ import annotations

from pathlib import Path

from core.entropy import find_high_entropy_candidates
from core.fs_walk import (
    check_permissive_permissions,
    classify_file,
    iter_target_files,
    read_text_safely,
)
from core.models import Finding, Severity, redact
from core.pe_utils import extract_strings_from_bytes, is_pe_file, parse_pe
from core.rules import Rule, load_rules

# Placeholder/test values that regex rules commonly false-positive on.
# Evidence matching these (case-insensitive) is downgraded to Low confidence
# rather than dropped entirely, so analysts can still eyeball and dismiss.
PLACEHOLDER_MARKERS = {
    "changeme", "changeit", "example", "your_api_key", "xxxxxxxx",
    "password", "12345678", "test123", "dummy", "placeholder",
    "insert_key_here", "todo", "yourpassword", "secret",
}


def _looks_like_placeholder(evidence: str) -> bool:
    lowered = evidence.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _confidence_for(evidence: str, base: str = "Medium") -> str:
    if _looks_like_placeholder(evidence):
        return "Low"
    return base


def _build_text_poc(file_path: str, line_no: int, rule_id: str, evidence_raw: str) -> str:
    """Build a reproducible, analyst-ready PoC block for a text/config-file match."""
    filename = Path(file_path).name
    search_term = evidence_raw[:20].split()[0] if evidence_raw.strip() else rule_id
    return (
        f"1. Open the file directly:\n"
        f"     {file_path}\n"
        f"   and go to line {line_no}.\n\n"
        f"2. Reproduce the detection independently:\n"
        f"   Windows (PowerShell):\n"
        f"     Select-String -Path \"{file_path}\" -Pattern \"{rule_id}\" -SimpleMatch:$false\n"
        f"   Linux/macOS:\n"
        f"     grep -n -i '{search_term}' \"{file_path}\"\n\n"
        f"3. Confirm exploitability: if this is a live/production credential, attempt "
        f"authentication against the associated service using the value found at "
        f"line {line_no} of {filename} (in an authorized test window only) to "
        f"confirm it is active before including it as a confirmed finding rather "
        f"than a potential one.\n\n"
        f"4. Evidence capture for the report: screenshot the line in context."
    )


def _build_entropy_poc(file_path: str, line_no: int, evidence_redacted: str) -> str:
    return (
        f"1. Open {file_path} at line {line_no} and manually inspect the "
        f"high-entropy token in context — entropy scoring flags candidates, "
        f"it does not confirm they are secrets.\n\n"
        f"2. Cross-reference the token format against known credential patterns "
        f"(length, charset, prefix) to identify the likely secret type (API key, "
        f"session token, encryption key, etc.).\n\n"
        f"3. If it resembles a live credential, test it against the likely "
        f"issuing service in an authorized test window to confirm activity "
        f"before escalating severity in the final report.\n\n"
        f"4. Evidence for this finding: {evidence_redacted}"
    )


def _build_binary_poc(file_path: str, evidence_redacted: str) -> str:
    filename = Path(file_path).name
    return (
        f"1. Extract printable strings from the binary directly to confirm "
        f"independently:\n"
        f"   Windows (Sysinternals strings.exe):\n"
        f"     strings64.exe -n 6 \"{file_path}\" | findstr /i \"{evidence_redacted[:8]}\"\n"
        f"   Linux:\n"
        f"     strings -n 6 \"{file_path}\" | grep -i '{evidence_redacted[:8]}'\n\n"
        f"2. Open {filename} in a PE viewer (CFF Explorer, Detect It Easy, or "
        f"IDA/Ghidra) and locate the string in the resource/data section to "
        f"confirm it is not dead code or a leftover debug string.\n\n"
        f"3. If confirmed live, treat this the same as a config-file secret: "
        f"rotate the credential and remove it from the compiled binary — "
        f"hardcoded strings in compiled code are trivially recoverable with "
        f"basic reverse-engineering tools regardless of packing.\n\n"
        f"4. Evidence: {evidence_redacted}"
    )


def _build_permission_poc(file_path: str) -> str:
    return (
        f"1. Confirm the permissive ACL directly:\n"
        f"   Windows:\n"
        f"     icacls \"{file_path}\"\n"
        f"   Linux/macOS:\n"
        f"     ls -l \"{file_path}\"\n\n"
        f"2. As a low-privileged local user (not administrator), attempt to "
        f"write to the file to confirm exploitability:\n"
        f"   Windows (PowerShell):\n"
        f"     Add-Content -Path \"{file_path}\" -Value \"poc-write-test\"\n"
        f"   Linux/macOS:\n"
        f"     echo poc-write-test >> \"{file_path}\"\n\n"
        f"3. If the write succeeds under a non-privileged account, this "
        f"confirms a low-privileged user can tamper with or exfiltrate the "
        f"secrets identified in this file. Revert the test write before "
        f"closing out the finding."
    )


def _scan_text_content(
    content: str,
    file_path: str,
    rules: list[Rule],
    enable_entropy: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # --- Regex rule matches, tracked with line numbers ---
    for rule in rules:
        for match in rule.finditer(content):
            evidence_raw = match.group(0)
            line_no = content.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    module="secrets",
                    rule_id=rule.id,
                    title=rule.description,
                    severity=rule.severity,
                    file_path=file_path,
                    evidence=evidence_raw,
                    description=(
                        f"Pattern matching rule '{rule.id}' ({rule.description}) "
                        f"was found in this file."
                    ),
                    remediation=(
                        "Remove hardcoded credentials/secrets from source and "
                        "configuration files. Use a secrets manager (Azure Key "
                        "Vault, AWS Secrets Manager, HashiCorp Vault) or environment "
                        "variables injected at runtime, and rotate the exposed "
                        "credential immediately."
                    ),
                    poc=_build_text_poc(file_path, line_no, rule.id, evidence_raw),
                    line_number=line_no,
                    tags=rule.tags,
                    confidence=_confidence_for(evidence_raw),
                )
            )

    # --- Entropy-based catch-all for secrets with no known pattern ---
    if enable_entropy:
        for candidate, offset in find_high_entropy_candidates(content):
            # Skip candidates already captured by a regex rule to avoid duplicate
            # noise for the same underlying string.
            if any(candidate == f.evidence for f in findings):
                continue
            line_no = content.count("\n", 0, offset) + 1
            findings.append(
                Finding(
                    module="secrets",
                    rule_id="high-entropy-string",
                    title="High-entropy string (possible unrecognized secret)",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    evidence=candidate,
                    description=(
                        "A string with unusually high randomness (Shannon entropy) "
                        "was found, which often indicates an API key, token, or "
                        "password that doesn't match a known vendor pattern."
                    ),
                    remediation=(
                        "Manually review this value. If it is a credential or "
                        "token, remove it from the file, rotate it, and load it "
                        "via a secrets manager or environment variable instead."
                    ),
                    line_number=line_no,
                    tags=["entropy", "generic"],
                    confidence="Low",  # entropy hits are inherently noisier
                    poc=_build_entropy_poc(file_path, line_no, candidate),
                )
            )

    return findings


def _scan_pe_strings(
    pe_path: Path,
    rules: list[Rule],
    enable_entropy: bool,
) -> list[Finding]:
    """Extract embedded strings from a PE file and run the same rule engine."""
    findings: list[Finding] = []
    try:
        data = pe_path.read_bytes()
    except OSError:
        return findings

    strings_with_offsets = extract_strings_from_bytes(data)
    if not strings_with_offsets:
        return findings

    # Concatenate extracted strings with newline separators so the same
    # line-based regex scanning logic can run unmodified against binary
    # content, while preserving byte offsets for reporting.
    joined = "\n".join(s for s, _ in strings_with_offsets)
    text_findings = _scan_text_content(joined, str(pe_path), rules, enable_entropy)

    # Re-map line-number placeholders to byte offsets where possible, and
    # tag these findings as binary-origin for the report.
    for f in text_findings:
        f.tags = list(set(f.tags + ["embedded-in-binary"]))
        f.description += " (Extracted from embedded strings inside a PE binary.)"
        f.poc = _build_binary_poc(str(pe_path), f.evidence)
    findings.extend(text_findings)

    return findings


def _flag_permissions(path: Path, related_findings: list[Finding]) -> list[Finding]:
    """If a file has sensitive findings, also check/report its permissions."""
    if not related_findings:
        return []

    perm_info = check_permissive_permissions(path)
    findings: list[Finding] = []

    if perm_info.get("world_writable"):
        findings.append(
            Finding(
                module="secrets",
                rule_id="world-writable-sensitive-file",
                title="World-writable file containing sensitive data",
                severity=Severity.HIGH,
                file_path=str(path),
                evidence="File permission bits include world-write (o+w)",
                description=(
                    "This file contains one or more detected secrets/credentials "
                    "and is writable by any local user, allowing tampering or "
                    "credential theft by a low-privileged local account."
                ),
                remediation=(
                    "Restrict file ACLs so only the application's service "
                    "account and administrators have write access."
                ),
                tags=["permissions", "acl"],
                confidence="Medium",
                poc=_build_permission_poc(str(path)),
            )
        )

    if perm_info.get("note") and perm_info["platform_checked"] == "Windows":
        # Informational: analyst should follow up with icacls on Windows hosts.
        findings.append(
            Finding(
                module="secrets",
                rule_id="acl-check-limited",
                title="ACL inspection limited on this platform",
                severity=Severity.INFO,
                file_path=str(path),
                evidence=perm_info["note"],
                description="Static ACL review was limited; verify manually.",
                remediation="Run `icacls <file>` on the target Windows host to confirm effective permissions.",
                tags=["permissions", "acl", "gap"],
                confidence="Low",
            )
        )

    return findings


def run(
    target_dir: str | Path,
    rules_dir: str | Path | None = None,
    enable_entropy: bool = True,
    scan_pe_strings: bool = True,
    progress_callback=None,
) -> list[Finding]:
    """
    Entry point for Module 1. Walks `target_dir`, scans every eligible file,
    and returns a deduplicated list of Finding objects.

    Args:
        target_dir: root directory of the extracted/installed application.
        rules_dir: optional override directory for YAML rule packs.
        enable_entropy: toggle entropy-based catch-all detection.
        scan_pe_strings: toggle embedded-string scanning of .exe/.dll files.
        progress_callback: optional callable(file_path: str) invoked per file,
            for CLI progress reporting.
    """
    target_dir = Path(target_dir)
    rules = load_rules(Path(rules_dir) if rules_dir else None)

    all_findings: list[Finding] = []
    seen_fingerprints: set[str] = set()

    def _add(findings: list[Finding]):
        for f in findings:
            fp = f.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(f)

    for path in iter_target_files(target_dir):
        if progress_callback:
            progress_callback(str(path))

        kind = classify_file(path)
        file_findings: list[Finding] = []

        if kind == "text":
            content = read_text_safely(path)
            if content:
                file_findings = _scan_text_content(content, str(path), rules, enable_entropy)

        elif kind == "pe" and scan_pe_strings and is_pe_file(path):
            file_findings = _scan_pe_strings(path, rules, enable_entropy)

        elif kind == "db":
            # v1: sniff raw bytes for plaintext PII/credential patterns only;
            # no structured DB parsing (SQLite page format, Access JET) yet.
            try:
                raw = path.read_bytes()[: 20 * 1024 * 1024]
                content = raw.decode("utf-8", errors="ignore")
            except OSError:
                content = ""
            if content:
                file_findings = _scan_text_content(content, str(path), rules, enable_entropy)
                for f in file_findings:
                    f.tags = list(set(f.tags + ["local-database"]))

        if file_findings:
            _add(file_findings)
            _add(_flag_permissions(path, file_findings))

    return all_findings
