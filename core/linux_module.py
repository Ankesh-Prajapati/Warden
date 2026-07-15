"""
Module 5 — Linux Thick-Client Static Security Assessment.

Statically assesses an extracted/installed Linux desktop application tree —
NOT the host OS. Covers, per the project spec:

  Application Discovery    — install metadata (.desktop, dpkg control, rpm
                              spec), discovered ELF executables
  Binary Analysis          — ELF header facts, hardening flags (PIE/NX),
                              embedded strings -> URLs/IPs/emails/endpoints
  Configuration Analysis   — inventory of config files present
  Sensitive Data Discovery — reuses secrets_module's rule+entropy engine
  Local Database Analysis  — SQLite/embedded DB inventory + secret scan
  Log Analysis             — log file inventory + secret scan
  Certificate Analysis     — bundled cert files: expired/self-signed/weak
  Update Mechanism Analysis— update URLs, HTTPS usage, signature-verify hints
  File Permission Analysis — world-writable app/config/cache/log paths
  Third-Party Libraries    — NEEDED shared libraries linked by each ELF
  Network Artifact Discovery — internal hosts / dev-staging URLs found
  Platform-specific        — systemd unit files, cron jobs, startup scripts

Reuses core/secrets_module.py (rule+entropy engine), core/fs_walk.py, and
core/binary_utils.py / core/cert_utils.py. Does not import or modify any
Windows-only module.
"""
from __future__ import annotations

import re
from pathlib import Path

from core import secrets_module
from core.binary_utils import parse_elf
from core.cert_utils import CERT_EXTENSIONS, analyze_certificate_file
from core.fs_walk import (
    check_permissive_permissions,
    find_elf_files,
    iter_all_files,
    read_text_safely,
)
from core.indicator_utils import (
    classify_internal_host,
    extract_api_endpoints,
    extract_emails,
    extract_urls,
)
from core.models import Finding, Severity

URL_RE = re.compile(r"https?://[^\s\"'<>]{4,300}")
UPDATE_KEYWORDS = ("update", "autoupdate", "upgrade", "appimageupdate")
TRUST_KEYWORDS = ("gpg", "signature", "sha256sum", "verify", "checksum", "publickey")

STATUS_SEVERITY = {
    "Pass": Severity.INFO,
    "Info": Severity.INFO,
    "Warning": Severity.LOW,
    "Fail": Severity.HIGH,
}


def _mk(category: str, check_name: str, status: str, evidence: str, description: str,
        recommendation: str, file_path: str = "", severity: Severity | None = None,
        confidence: str = "Medium", tags: list[str] | None = None) -> Finding:
    sev = severity or STATUS_SEVERITY.get(status, Severity.INFO)
    rule_id = f"linux-{category.lower().replace(' ', '-')}-{check_name.lower().replace(' ', '-')}"
    return Finding(
        module="linux",
        rule_id=rule_id,
        title=f"[{category}] {check_name}",
        severity=sev,
        file_path=file_path,
        evidence=evidence,
        description=description,
        remediation=recommendation,
        tags=list(set((tags or []) + ["linux", category.lower().replace(" ", "-")])),
        confidence=confidence,
        extra={"category": category, "status": status, "platform": "linux"},
    )


def _application_discovery(target_dir: Path, elf_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []

    for p in iter_all_files(target_dir):
        name = p.name
        content = None
        if name.endswith(".desktop"):
            content = read_text_safely(p)
            fields = {}
            for line in content.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    fields[k.strip()] = v.strip()
            findings.append(_mk(
                "Application Discovery", "Desktop Entry Metadata", "Info",
                evidence=f"Name={fields.get('Name', '?')}, Exec={fields.get('Exec', '?')}, "
                         f"Version={fields.get('Version', 'unspecified')}",
                description="A .desktop launcher entry describes how this application is installed and launched.",
                recommendation="Confirm the Exec= command does not invoke the binary with unsafe world-writable paths.",
                file_path=str(p),
            ))
        elif name == "control" and "DEBIAN" in p.parts:
            content = read_text_safely(p)
            findings.append(_mk(
                "Application Discovery", "Debian Package Metadata", "Info",
                evidence=content[:300],
                description="Debian package control file identifies package name, version, and maintainer.",
                recommendation="Verify the declared version matches the actual installed binary version.",
                file_path=str(p),
            ))
        elif p.suffix == ".spec":
            content = read_text_safely(p)
            findings.append(_mk(
                "Application Discovery", "RPM Spec Metadata", "Info",
                evidence=content[:300],
                description="RPM spec file identifies package name and version metadata.",
                recommendation="Verify the declared version matches the actual installed binary version.",
                file_path=str(p),
            ))

    findings.append(_mk(
        "Application Discovery", "ELF Executables Discovered",
        "Info" if elf_files else "Warning",
        evidence=f"{len(elf_files)} ELF file(s) found under {target_dir}",
        description="Inventory of all ELF binaries/libraries found in the application tree.",
        recommendation="Confirm every shipped binary is expected/signed by the vendor's build process.",
        file_path=str(target_dir),
    ))
    return findings


def _binary_analysis(elf_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    from core.pe_utils import extract_strings_from_bytes  # generic byte-string extractor, not PE-specific

    for path in elf_files:
        info = parse_elf(path)
        if not info.is_valid_elf:
            continue

        findings.append(_mk(
            "Binary Analysis", "ELF Header Summary", "Info",
            evidence=f"arch={info.machine}, type={info.elf_type}, 64-bit={info.is_64bit}",
            description="Basic ELF header facts for this binary.",
            recommendation="No action needed; informational.",
            file_path=str(path),
        ))

        if info.elf_type == "Executable" and not info.is_pie:
            findings.append(_mk(
                "Binary Analysis", "Position Independent Executable (PIE)", "Fail",
                evidence="Binary is type ET_EXEC (non-PIE)",
                description="This executable is not built as a Position Independent Executable, weakening ASLR effectiveness.",
                recommendation="Rebuild with -pie -fPIE so the loader can randomize the base address.",
                file_path=str(path), severity=Severity.MEDIUM,
            ))

        if info.nx_stack is False:
            findings.append(_mk(
                "Binary Analysis", "Executable Stack (NX)", "Fail",
                evidence="GNU_STACK segment is executable",
                description="The binary's stack segment is marked executable, weakening exploit mitigation.",
                recommendation="Rebuild without -z execstack; ensure the toolchain emits a non-executable GNU_STACK.",
                file_path=str(path), severity=Severity.MEDIUM,
            ))

        if info.rpath_runpath:
            findings.append(_mk(
                "Binary Analysis", "RPATH/RUNPATH Present", "Warning",
                evidence=", ".join(info.rpath_runpath),
                description="A hardcoded RPATH/RUNPATH can enable library-hijacking if the referenced directory is writable.",
                recommendation="Remove hardcoded RPATH/RUNPATH or ensure referenced directories are not writable by unprivileged users.",
                file_path=str(path),
            ))

        try:
            data = path.read_bytes()
        except OSError:
            continue
        strings_only = [s for s, _ in extract_strings_from_bytes(data)]
        joined = "\n".join(strings_only)
        for label, hits in (
            ("URL", extract_urls(joined)),
            ("email address", extract_emails(joined)),
            ("API endpoint", extract_api_endpoints(joined)),
        ):
            if hits:
                findings.append(_mk(
                    "Binary Analysis", f"Embedded {label}(s)", "Info",
                    evidence="; ".join(hits),
                    description=f"Embedded strings inside the binary reveal {label}(s), useful for attack-surface mapping. "
                                f"Common license/schema/registry boilerplate has already been filtered out.",
                    recommendation="Confirm none of these reference internal/staging infrastructure that shouldn't be reachable externally.",
                    file_path=str(path),
                    confidence="Medium" if label == "URL" else "Low",
                ))
    return findings


def _config_and_secrets(target_dir: Path, rules_dir, enable_entropy: bool, single_file) -> list[Finding]:
    """Reuses Module 1's rule+entropy engine, then re-buckets the resulting
    findings into the Linux assessment's category taxonomy instead of
    duplicating that scanning logic."""
    raw = secrets_module.run(
        target_dir=target_dir, rules_dir=rules_dir, enable_entropy=enable_entropy,
        scan_pe_strings=False, single_file=single_file,
    )
    findings: list[Finding] = []
    for f in raw:
        ext = Path(f.file_path).suffix.lower()
        if ext == ".log":
            category = "Log Analysis"
        elif ext in {".sqlite", ".sqlite3", ".db"}:
            category = "Local Database Analysis"
        else:
            category = "Sensitive Data Discovery"
        f.module = "linux"
        f.title = f"[{category}] {f.title}"
        f.extra["category"] = category
        f.extra["platform"] = "linux"
        f.tags = list(set(f.tags + ["linux", category.lower().replace(" ", "-")]))
        findings.append(f)

    config_files = [p for p in iter_all_files(target_dir)
                    if p.suffix.lower() in {".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml", ".env"}]
    if config_files:
        findings.append(_mk(
            "Configuration Analysis", "Configuration Files Inventoried", "Info",
            evidence=f"{len(config_files)} configuration file(s) found",
            description="Inventory of configuration files parsed for this assessment.",
            recommendation="Review configuration files for insecure defaults (debug mode, permissive CORS, verbose logging).",
            file_path=str(target_dir),
        ))
    return findings


def _certificate_analysis(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in iter_all_files(target_dir):
        if p.suffix.lower() not in CERT_EXTENSIONS:
            continue
        cert = analyze_certificate_file(p)
        if cert.error:
            continue
        if cert.is_expired:
            findings.append(_mk(
                "Certificate Analysis", "Expired Certificate", "Fail",
                evidence=f"subject={cert.subject_cn}, not_valid_after={cert.not_valid_after}",
                description="A bundled certificate has expired.",
                recommendation="Replace the expired certificate and rotate any keys tied to it.",
                file_path=str(p), severity=Severity.HIGH,
            ))
        # Root/intermediate CA certificates are *expected* to be self-signed
        # by design (that's what makes them a trust anchor) — only flag
        # self-signed for end-entity (non-CA) certs, where it's a real
        # anti-pattern (e.g. a self-signed TLS leaf cert used in production).
        if cert.is_self_signed and not cert.is_ca_certificate:
            findings.append(_mk(
                "Certificate Analysis", "Self-Signed Certificate", "Warning",
                evidence=f"subject={cert.subject_cn}",
                description="A bundled end-entity certificate is self-signed rather than issued by a trusted CA.",
                recommendation="Use a CA-issued certificate for any TLS/trust-anchor purpose in production.",
                file_path=str(p), confidence="Medium",
            ))
        # A self-signed root CA's own signature algorithm doesn't carry
        # security weight (trust is anchored by out-of-band distribution,
        # not by the signature) — many long-lived, still-legitimate roots
        # use SHA-1. Only flag weak algorithms on non-CA certs.
        if cert.is_weak_algorithm and not cert.is_ca_certificate:
            findings.append(_mk(
                "Certificate Analysis", "Weak Signature Algorithm", "Fail",
                evidence=f"algorithm={cert.signature_algorithm}",
                description="Certificate uses a weak/deprecated signature hash algorithm (MD5/SHA-1).",
                recommendation="Reissue the certificate using SHA-256 or stronger.",
                file_path=str(p), severity=Severity.HIGH,
            ))
    return findings


def _update_mechanism_analysis(target_dir: Path, elf_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    from core.pe_utils import extract_strings_from_bytes

    candidates: list[tuple[str, str]] = []  # (source_path, text)
    for p in elf_files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        strings_only = [s for s, _ in extract_strings_from_bytes(data)]
        candidates.append((str(p), "\n".join(strings_only)))
    for p in iter_all_files(target_dir):
        if p.suffix.lower() in {".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".desktop"}:
            content = read_text_safely(p)
            if content:
                candidates.append((str(p), content))

    seen_urls = set()
    for path_str, text in candidates:
        lowered = text.lower()
        if not any(k in lowered for k in UPDATE_KEYWORDS):
            continue
        for url in URL_RE.findall(text):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if url.startswith("http://"):
                findings.append(_mk(
                    "Update Mechanism Analysis", "Insecure Update URL (HTTP)", "Fail",
                    evidence=url,
                    description="An update-related URL uses plaintext HTTP, exposing update payloads to MITM tampering.",
                    recommendation="Serve update manifests and payloads exclusively over HTTPS.",
                    file_path=path_str, severity=Severity.HIGH,
                ))
            else:
                has_trust_signal = any(k in lowered for k in TRUST_KEYWORDS)
                findings.append(_mk(
                    "Update Mechanism Analysis", "Update URL Uses HTTPS", "Pass" if has_trust_signal else "Warning",
                    evidence=url,
                    description="Update mechanism uses HTTPS." + ("" if has_trust_signal else
                        " No signature/checksum verification keywords were found nearby."),
                    recommendation="Ensure downloaded update packages are verified (GPG signature or SHA-256 checksum) before being applied.",
                    file_path=path_str,
                ))
    return findings


def _file_permission_analysis(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    interesting_names = {"config", "cache", "logs", "log", "data", "bin"}
    checked = 0
    for p in iter_all_files(target_dir):
        if checked >= 500:  # bound cost on very large trees
            break
        if p.parent.name.lower() in interesting_names or p.suffix.lower() in {".conf", ".cfg", ".log", ".json"}:
            checked += 1
            perm = check_permissive_permissions(p)
            if perm.get("world_writable"):
                findings.append(_mk(
                    "File Permission Analysis", "World-Writable File", "Fail",
                    evidence="Mode bits include world-write (o+w)",
                    description="A configuration, cache, or log file is writable by any local user.",
                    recommendation="Restrict permissions (chmod o-w) so only the application's own user can write to it.",
                    file_path=str(p), severity=Severity.MEDIUM,
                ))
    return findings


def _third_party_libraries(elf_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    all_libs: set[str] = set()
    for p in elf_files:
        info = parse_elf(p)
        all_libs.update(info.needed_libraries)
    if all_libs:
        findings.append(_mk(
            "Third-Party Library Enumeration", "Linked Shared Libraries", "Info",
            evidence=", ".join(sorted(all_libs)[:30]),
            description=f"{len(all_libs)} unique shared libraries (DT_NEEDED) are linked across discovered ELF binaries.",
            recommendation="Cross-reference these libraries and their bundled versions against known CVEs.",
            file_path="",
        ))
    return findings


def _network_artifacts(all_findings: list[Finding]) -> list[Finding]:
    """Surface internal/dev-looking hosts already discovered as embedded
    strings during Binary Analysis, as their own explicit category."""
    findings: list[Finding] = []
    seen = set()
    for f in all_findings:
        if f.extra.get("category") != "Binary Analysis" or "URL" not in f.title:
            continue
        for url in f.evidence.split("; "):
            if url in seen:
                continue
            # Classifies against the *parsed hostname*, not a raw substring
            # of the URL — avoids false positives like "test." incorrectly
            # matching inside an unrelated domain such as "latest.com".
            if classify_internal_host(url):
                seen.add(url)
                findings.append(_mk(
                    "Network Artifact Discovery", "Internal/Development Endpoint Referenced", "Warning",
                    evidence=url,
                    description="A binary references what appears to be an internal, staging, or development endpoint.",
                    recommendation="Ensure internal/dev endpoints are not reachable from or shipped in production builds.",
                    file_path=f.file_path, confidence="Medium",
                ))
    return findings


def _startup_and_scheduling(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in iter_all_files(target_dir):
        if p.suffix == ".service":
            content = read_text_safely(p)
            findings.append(_mk(
                "Startup", "Systemd Unit File", "Info",
                evidence=content[:300],
                description="A systemd service unit shipped by this application controls its startup behavior.",
                recommendation="Verify the unit does not run as root unless strictly required, and that ExecStart paths are not writable by other users.",
                file_path=str(p),
            ))
            user_match = re.search(r"^\s*User\s*=\s*(\S+)", content, re.MULTILINE)
            runs_as_root = (user_match is None) or (user_match.group(1) == "root")
            if runs_as_root:
                findings.append(_mk(
                    "Startup", "Service Runs as Root", "Warning",
                    evidence=("No User= directive found (systemd defaults to root)" if user_match is None
                              else "User=root explicitly set"),
                    description="The systemd unit does not drop privileges to a non-root user.",
                    recommendation="Add a dedicated unprivileged service account via User=/Group= directives.",
                    file_path=str(p),
                ))
        if p.name in {"crontab", "cron.d"} or "cron" in p.parts:
            content = read_text_safely(p)
            if content.strip():
                findings.append(_mk(
                    "Startup", "Cron Job Shipped With Application", "Info",
                    evidence=content[:300],
                    description="A cron schedule file is bundled with the application.",
                    recommendation="Confirm the scheduled command path is not writable by unprivileged users.",
                    file_path=str(p),
                ))
    return findings


def run(
    target_dir: str | Path,
    rules_dir: str | Path | None = None,
    enable_entropy: bool = True,
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
) -> list[Finding]:
    """Entry point for the Linux thick-client static assessment module."""
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None

    elf_files = find_elf_files(target_dir, single_file=single_file)
    if progress_callback:
        for p in elf_files:
            progress_callback(str(p))

    findings: list[Finding] = []
    try:
        findings.extend(_application_discovery(target_dir, elf_files))
        findings.extend(_binary_analysis(elf_files))
        findings.extend(_config_and_secrets(target_dir, rules_dir, enable_entropy, single_file))
        findings.extend(_certificate_analysis(target_dir))
        findings.extend(_update_mechanism_analysis(target_dir, elf_files))
        findings.extend(_file_permission_analysis(target_dir))
        findings.extend(_third_party_libraries(elf_files))
        findings.extend(_startup_and_scheduling(target_dir))
        findings.extend(_network_artifacts(findings))
    except Exception as e:
        if error_callback:
            error_callback(f"linux module: {e}")

    return findings
