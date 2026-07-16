"""
Module 6 — macOS Thick-Client Static Security Assessment.

Statically assesses an extracted/installed macOS .app bundle — NOT the host
OS. Covers, per the project spec:

  Application Discovery    — Info.plist metadata (bundle id, version, exec)
  Binary Analysis          — Mach-O header facts, embedded strings ->
                              URLs/IPs/emails/endpoints, code-signing status
  Configuration Analysis   — plist/config file inventory
  Sensitive Data Discovery — reuses secrets_module's rule+entropy engine
  Local Database Analysis  — SQLite/embedded DB inventory + secret scan
  Log Analysis             — log file inventory + secret scan
  Certificate Analysis     — bundled cert files: expired/self-signed/weak
  Update Mechanism Analysis— Sparkle feed URL / HTTPS / EdDSA-signature hints
  File Permission Analysis — world-writable bundle/config/cache/log paths
  Third-Party Libraries    — linked dylibs + embedded Frameworks
  Network Artifact Discovery — internal hosts / dev-staging URLs found
  Platform-specific        — LaunchAgents/Daemons, entitlements, Keychain
                              usage, embedded frameworks

Reuses core/secrets_module.py (rule+entropy engine), core/fs_walk.py, and
core/binary_utils.py / core/cert_utils.py. Does not import or modify any
Windows-only module.
"""
from __future__ import annotations

import plistlib
import re
import shutil
from pathlib import Path

from core import secrets_module
from core.binary_utils import parse_macho
from core.cert_utils import CERT_EXTENSIONS, analyze_certificate_file
from core.fs_walk import (
    check_permissive_permissions,
    find_macho_files,
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

SPARKLE_MARKERS = ("sparkle", "sufeedurl", "appcast")
KEYCHAIN_MARKERS = ("securaddgenericpassword", "securitemadd", "sectransform", "keychain")
INVENTORY_TAG = "inventory"

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
    rule_id = f"macos-{category.lower().replace(' ', '-')}-{check_name.lower().replace(' ', '-')}"
    return Finding(
        module="macos",
        rule_id=rule_id,
        title=f"[{category}] {check_name}",
        severity=sev,
        file_path=file_path,
        evidence=evidence,
        description=description,
        remediation=recommendation,
        tags=list(set((tags or []) + ["macos", category.lower().replace(" ", "-")])),
        confidence=confidence,
        extra={"category": category, "status": status, "platform": "macos"},
    )


def _load_plist(path: Path) -> dict:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return {}


def _application_discovery(target_dir: Path, macho_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in iter_all_files(target_dir):
        if p.name == "Info.plist":
            data = _load_plist(p)
            if not data:
                continue
            findings.append(_mk(
                "Application Discovery", "Info.plist Bundle Metadata", "Info",
                evidence=(f"CFBundleIdentifier={data.get('CFBundleIdentifier', '?')}, "
                          f"CFBundleShortVersionString={data.get('CFBundleShortVersionString', '?')}, "
                          f"CFBundleExecutable={data.get('CFBundleExecutable', '?')}"),
                description="App bundle metadata identifies the application, version, and main executable.",
                recommendation="Confirm the bundle identifier and version match the vendor's published release.",
                file_path=str(p),
                tags=[INVENTORY_TAG],
            ))
            if data.get("NSAppTransportSecurity", {}).get("NSAllowsArbitraryLoads"):
                findings.append(_mk(
                    "Application Discovery", "App Transport Security Disabled", "Fail",
                    evidence="NSAllowsArbitraryLoads = true",
                    description="App Transport Security is globally disabled, permitting insecure (non-HTTPS) network connections.",
                    recommendation="Remove NSAllowsArbitraryLoads and use per-domain exceptions only where strictly justified.",
                    file_path=str(p), severity=Severity.HIGH,
                ))
            for scheme in data.get("CFBundleURLTypes", []) or []:
                schemes = scheme.get("CFBundleURLSchemes", []) if isinstance(scheme, dict) else []
                for url_scheme in schemes:
                    lowered = str(url_scheme).lower()
                    severity = Severity.MEDIUM if lowered in {"http", "https", "file"} else Severity.LOW
                    findings.append(_mk(
                        "Application Discovery", "Custom URL Scheme Registered", "Warning",
                        evidence=str(url_scheme),
                        description="The app registers a custom URL scheme, which can expand attack surface through external app invocation.",
                        recommendation="Validate and sanitize all URL-scheme inputs; avoid generic schemes such as http, https, or file.",
                        file_path=str(p),
                        severity=severity,
                        tags=["url-scheme"],
                    ))
            if data.get("LSFileQuarantineEnabled") is False:
                findings.append(_mk(
                    "Application Discovery", "File Quarantine Disabled", "Warning",
                    evidence="LSFileQuarantineEnabled = false",
                    description="The app explicitly disables file quarantine tagging for files it creates.",
                    recommendation="Keep file quarantine enabled unless there is a documented business need and compensating validation.",
                    file_path=str(p),
                    severity=Severity.MEDIUM,
                    tags=["quarantine"],
                ))

    findings.append(_mk(
        "Application Discovery", "Mach-O Binaries Discovered",
        "Info" if macho_files else "Warning",
        evidence=f"{len(macho_files)} Mach-O file(s) found under {target_dir}",
        description="Inventory of all Mach-O executables/libraries/frameworks found in the app bundle.",
        recommendation="Confirm every shipped binary is expected/signed by the vendor's build process.",
        file_path=str(target_dir),
        tags=[INVENTORY_TAG],
    ))
    return findings


def _binary_analysis(macho_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    from core.pe_utils import extract_strings_from_bytes

    for path in macho_files:
        info = parse_macho(path)
        if not info.is_valid_macho:
            continue

        findings.append(_mk(
            "Binary Analysis", "Mach-O Header Summary", "Info",
            evidence=f"variant={info.variant}",
            description="Basic Mach-O identification for this binary.",
            recommendation="No action needed; informational.",
            file_path=str(path),
            tags=[INVENTORY_TAG],
        ))

        if info.codesign_status == "unsigned":
            findings.append(_mk(
                "Binary Analysis", "Code Signature", "Fail",
                evidence="codesign reports this binary as unsigned",
                description="This binary is not code-signed, so Gatekeeper and system integrity checks cannot verify its origin.",
                recommendation="Sign the binary with a valid Developer ID certificate and notarize the app.",
                file_path=str(path), severity=Severity.HIGH,
            ))
        elif info.codesign_status == "signed":
            findings.append(_mk(
                "Binary Analysis", "Code Signature", "Pass",
                evidence="codesign reports this binary as signed",
                description="Binary carries a code signature.",
                recommendation="No action needed.",
                file_path=str(path),
                tags=[INVENTORY_TAG],
            ))

        if info.hardened_runtime is False:
            findings.append(_mk(
                "Binary Analysis", "Hardened Runtime Not Detected", "Warning",
                evidence="codesign flags do not include runtime",
                description="The binary appears signed without Apple's hardened runtime option.",
                recommendation="Sign distribution builds with the hardened runtime enabled and grant only required exceptions.",
                file_path=str(path),
                severity=Severity.MEDIUM,
                tags=["hardening", "codesign"],
            ))
        elif info.hardened_runtime is True:
            findings.append(_mk(
                "Binary Analysis", "Hardened Runtime Enabled", "Info",
                evidence="codesign flags include runtime",
                description="The binary appears to use Apple's hardened runtime.",
                recommendation="Keep hardened runtime enabled for notarized distribution builds.",
                file_path=str(path),
                tags=[INVENTORY_TAG, "hardening", "codesign"],
            ))

        if info.notarized is False:
            findings.append(_mk(
                "Binary Analysis", "Notarization Not Confirmed", "Warning",
                evidence="spctl did not report notarized acceptance",
                description="Notarization could not be confirmed for this executable.",
                recommendation="Notarize distributed macOS apps and verify with spctl on a clean macOS system.",
                file_path=str(path),
                tags=["notarization", "codesign"],
            ))
        elif info.notarized is True:
            findings.append(_mk(
                "Binary Analysis", "Notarization Confirmed", "Info",
                evidence="spctl reports notarized acceptance",
                description="Apple notarization was confirmed for this executable.",
                recommendation="Continue notarizing distribution builds.",
                file_path=str(path),
                tags=[INVENTORY_TAG, "notarization", "codesign"],
            ))

        if info.rpaths:
            findings.append(_mk(
                "Binary Analysis", "LC_RPATH Present", "Warning",
                evidence=", ".join(info.rpaths),
                description="A hardcoded runpath can enable dylib-hijacking if the referenced directory is writable.",
                recommendation="Remove hardcoded @rpath entries pointing to writable/user-controlled directories.",
                file_path=str(path),
            ))

        if info.entitlements_xml:
            ent_summary = ", ".join(sorted(info.entitlements.keys())) if info.entitlements else info.entitlements_xml[:300]
            findings.append(_mk(
                "Binary Analysis", "Entitlements Declared", "Info",
                evidence=ent_summary,
                description="The binary declares one or more entitlements controlling its sandbox/privilege scope.",
                recommendation="Verify each declared entitlement is actually required (principle of least privilege).",
                file_path=str(path),
                tags=[INVENTORY_TAG, "entitlements"],
            ))
            if info.entitlements.get("com.apple.security.get-task-allow") or "com.apple.security.get-task-allow" in info.entitlements_xml:
                findings.append(_mk(
                    "Binary Analysis", "Debuggable Entitlement in Release Binary", "Warning",
                    evidence="com.apple.security.get-task-allow present",
                    description="This entitlement allows another process to attach a debugger — appropriate for dev builds only.",
                    recommendation="Ensure this entitlement is stripped from release/distribution builds.",
                    file_path=str(path),
                    severity=Severity.MEDIUM,
                    tags=["entitlements", "debug"],
                ))
            risky_ents = {
                "com.apple.security.cs.disable-library-validation": "Library validation disabled",
                "com.apple.security.cs.allow-dyld-environment-variables": "DYLD environment variables allowed",
                "com.apple.security.cs.allow-unsigned-executable-memory": "Unsigned executable memory allowed",
                "com.apple.security.files.user-selected.executable": "User-selected executable file access",
            }
            for key, label in risky_ents.items():
                if info.entitlements.get(key):
                    findings.append(_mk(
                        "Binary Analysis", label, "Warning",
                        evidence=key,
                        description="A high-risk entitlement relaxes hardened runtime or file execution protections.",
                        recommendation="Remove this entitlement unless explicitly required and threat-modeled.",
                        file_path=str(path),
                        severity=Severity.MEDIUM,
                        tags=["entitlements", "hardening"],
                    ))

        try:
            data = path.read_bytes()
        except OSError:
            continue
        strings_only = [s for s, _ in extract_strings_from_bytes(data)]
        joined = "\n".join(strings_only)
        lowered = joined.lower()

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

        if any(k in lowered for k in KEYCHAIN_MARKERS):
            findings.append(_mk(
                "Binary Analysis", "Keychain API Usage", "Info",
                evidence="Keychain Services API symbol(s) referenced",
                description="Binary references macOS Keychain Services APIs, indicating it stores/retrieves secrets via Keychain.",
                recommendation="Confirm Keychain items use appropriate accessibility class (e.g. kSecAttrAccessibleWhenUnlockedThisDeviceOnly) rather than always-accessible.",
                file_path=str(path),
            ))
    return findings


def _config_and_secrets(target_dir: Path, rules_dir, enable_entropy: bool, single_file) -> list[Finding]:
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
        f.module = "macos"
        f.title = f"[{category}] {f.title}"
        f.extra["category"] = category
        f.extra["platform"] = "macos"
        f.tags = list(set(f.tags + ["macos", category.lower().replace(" ", "-")]))
        findings.append(f)

    config_files = [p for p in iter_all_files(target_dir)
                    if p.suffix.lower() in {".plist", ".json", ".yaml", ".yml", ".conf", ".ini"}]
    if config_files:
        findings.append(_mk(
            "Configuration Analysis", "Configuration Files Inventoried", "Info",
            evidence=f"{len(config_files)} configuration/plist file(s) found",
            description="Inventory of configuration files parsed for this assessment.",
            recommendation="Review configuration/plist files for insecure defaults (debug flags, verbose logging, disabled ATS).",
            file_path=str(target_dir),
            tags=[INVENTORY_TAG],
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
        if cert.is_self_signed and not cert.is_ca_certificate:
            findings.append(_mk(
                "Certificate Analysis", "Self-Signed Certificate", "Warning",
                evidence=f"subject={cert.subject_cn}",
                description="A bundled end-entity certificate is self-signed rather than issued by a trusted CA.",
                recommendation="Use a CA-issued certificate for any TLS/trust-anchor purpose in production.",
                file_path=str(p), confidence="Medium",
            ))
        if cert.is_weak_algorithm and not cert.is_ca_certificate:
            findings.append(_mk(
                "Certificate Analysis", "Weak Signature Algorithm", "Fail",
                evidence=f"algorithm={cert.signature_algorithm}",
                description="Certificate uses a weak/deprecated signature hash algorithm (MD5/SHA-1).",
                recommendation="Reissue the certificate using SHA-256 or stronger.",
                file_path=str(p), severity=Severity.HIGH,
            ))
    return findings


def _update_mechanism_analysis(target_dir: Path, macho_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    from core.pe_utils import extract_strings_from_bytes

    candidates: list[tuple[str, str]] = []
    for p in macho_files:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        strings_only = [s for s, _ in extract_strings_from_bytes(data)]
        candidates.append((str(p), "\n".join(strings_only)))
    for p in iter_all_files(target_dir):
        if p.name == "Info.plist":
            plist = _load_plist(p)
            feed = plist.get("SUFeedURL")
            if feed:
                key_marker = " SUPublicEDKey present" if "SUPublicEDKey" in plist else ""
                candidates.append((str(p), f"sparkle SUFeedURL {feed}{key_marker}"))
            if "SUPublicEDKey" in plist:
                candidates.append((str(p), "sparkle SUPublicEDKey present (EdDSA update signing configured)"))
        elif p.suffix.lower() in {".plist", ".conf", ".json"}:
            content = read_text_safely(p)
            if content:
                candidates.append((str(p), content))

    seen_urls = set()
    for path_str, text in candidates:
        lowered = text.lower()
        if not any(k in lowered for k in SPARKLE_MARKERS) and "update" not in lowered:
            continue
        has_eddsa = "supublicedkey" in lowered
        for url in URL_RE.findall(text):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            if url.startswith("http://"):
                findings.append(_mk(
                    "Update Mechanism Analysis", "Insecure Update/Sparkle Feed URL (HTTP)", "Fail",
                    evidence=url,
                    description="An update feed (e.g. Sparkle appcast) URL uses plaintext HTTP, exposing update payloads to MITM tampering.",
                    recommendation="Serve the appcast/update feed and payloads exclusively over HTTPS.",
                    file_path=path_str, severity=Severity.HIGH,
                ))
            else:
                findings.append(_mk(
                    "Update Mechanism Analysis", "Update/Sparkle Feed URL Uses HTTPS",
                    "Pass" if has_eddsa else "Warning",
                    evidence=url,
                    description="Update feed uses HTTPS." + ("" if has_eddsa else
                        " No Sparkle EdDSA signing key (SUPublicEDKey) was found — updates may not be signature-verified."),
                    recommendation="Configure Sparkle (or equivalent) EdDSA update signing (SUPublicEDKey) so payloads are verified before install.",
                    file_path=path_str,
                    tags=[INVENTORY_TAG] if has_eddsa else None,
                ))
    return findings


def _file_permission_analysis(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    interesting_names = {"resources", "contents", "logs", "log", "cache", "caches", "macos"}
    checked = 0
    for p in iter_all_files(target_dir):
        if checked >= 500:
            break
        if p.parent.name.lower() in interesting_names or p.suffix.lower() in {".plist", ".log", ".json", ".conf"}:
            checked += 1
            perm = check_permissive_permissions(p)
            if perm.get("world_writable"):
                findings.append(_mk(
                    "File Permission Analysis", "World-Writable File", "Fail",
                    evidence="Mode bits include world-write (o+w)",
                    description="A configuration, cache, or log file inside the app bundle is writable by any local user.",
                    recommendation="Restrict permissions (chmod o-w) so only the application's own user can write to it.",
                    file_path=str(p), severity=Severity.MEDIUM,
                ))
    return findings


def _third_party_libraries(target_dir: Path, macho_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    all_libs: set[str] = set()
    for p in macho_files:
        info = parse_macho(p)
        all_libs.update(info.linked_libraries)
    if all_libs:
        findings.append(_mk(
            "Third-Party Library Enumeration", "Linked Dynamic Libraries", "Info",
            evidence=", ".join(sorted(all_libs)[:30]),
            description=f"{len(all_libs)} unique dynamic libraries are linked across discovered Mach-O binaries.",
            recommendation="Cross-reference these libraries and their bundled versions against known CVEs.",
            file_path="",
            tags=[INVENTORY_TAG, "sbom"],
        ))

    frameworks = sorted({p.parent.name for p in iter_all_files(target_dir) if p.suffix == ".framework"
                          or ".framework" in str(p)})
    framework_dirs = sorted({str(pp) for pp in target_dir.rglob("*.framework")}) if target_dir.exists() else []
    if framework_dirs:
        findings.append(_mk(
            "Third-Party Library Enumeration", "Embedded Frameworks", "Info",
            evidence="; ".join(Path(f).name for f in framework_dirs[:30]),
            description=f"{len(framework_dirs)} embedded .framework bundle(s) found inside the app.",
            recommendation="Verify each embedded framework is signed and at a patched version.",
            file_path="",
            tags=[INVENTORY_TAG, "sbom"],
        ))
    versioned = sorted({lib for lib in all_libs if re.search(r"\.(?:dylib|framework)(?:/Versions/[A-Z])?", lib)})
    if versioned:
        findings.append(_mk(
            "Third-Party Library Enumeration", "Library Inventory for CVE Review", "Info",
            evidence=", ".join(versioned[:50]),
            description="Linked dynamic-library/framework names were extracted for SBOM/CVE correlation.",
            recommendation="Feed this inventory into your dependency/CVE workflow and verify bundled framework versions are patched.",
            file_path="",
            tags=[INVENTORY_TAG, "sbom", "cve"],
        ))
    return findings


def _network_artifacts(all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    seen = set()
    for f in all_findings:
        if f.extra.get("category") != "Binary Analysis" or "URL" not in f.title:
            continue
        for url in f.evidence.split("; "):
            if url in seen:
                continue
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


def _startup_items(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in iter_all_files(target_dir):
        lowered_parts = [part.lower() for part in p.parts]
        if p.suffix == ".plist" and ("launchagents" in lowered_parts or "launchdaemons" in lowered_parts):
            kind = "LaunchDaemon" if "launchdaemons" in lowered_parts else "LaunchAgent"
            data = _load_plist(p)
            findings.append(_mk(
                "Startup", f"{kind} Discovered", "Info",
                evidence=f"Label={data.get('Label', '?')}, RunAtLoad={data.get('RunAtLoad', False)}",
                description=f"A {kind} plist controls background execution of this application's helper process.",
                recommendation="Verify the referenced executable path is not writable by other users and runs with least privilege.",
                file_path=str(p),
                tags=[INVENTORY_TAG],
            ))
            if kind == "LaunchDaemon":
                user_name = data.get("UserName")
                if not user_name or user_name == "root":
                    findings.append(_mk(
                        "Startup", "LaunchDaemon Runs as Root", "Warning",
                        evidence="No UserName key found" if not user_name else "UserName=root",
                        description="This LaunchDaemon appears to run as root instead of dropping to an unprivileged user.",
                        recommendation="Confirm this component truly needs root-level system execution; set UserName to a dedicated service user if not.",
                        file_path=str(p),
                    ))
    return findings


def _tool_gap_findings(target_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    missing = [tool for tool in ("otool", "codesign") if shutil.which(tool) is None]
    if missing:
        findings.append(_mk(
            "Binary Analysis", "macOS Tooling Not Available", "Info",
            evidence="Missing tools: " + ", ".join(missing),
            description=(
                "Mach-O magic-byte discovery still runs, but linked library, RPATH, code-signing, "
                "and entitlement enrichment depend on macOS command-line tools."
            ),
            recommendation="Run the macOS module on macOS with Xcode Command Line Tools installed for deeper analysis.",
            file_path=str(target_dir),
            confidence="High",
            tags=["tooling-gap"],
        ))
    return findings


def _single_file_discovery(single_file: Path, macho_files: list[Path]) -> list[Finding]:
    return [_mk(
        "Application Discovery", "Single File Scope",
        "Info" if macho_files else "Warning",
        evidence=f"Single-file macOS scan target: {single_file}",
        description="The macOS module is restricted to the selected file; bundle-level Info.plist, startup, certificate, framework, and permission inventory is skipped.",
        recommendation="Run a folder scan against the full .app bundle for complete macOS thick-client coverage.",
        file_path=str(single_file),
    )]


def run(
    target_dir: str | Path,
    rules_dir: str | Path | None = None,
    enable_entropy: bool = True,
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
    include_inventory: bool = True,
) -> list[Finding]:
    """Entry point for the macOS thick-client static assessment module."""
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None

    macho_files = find_macho_files(target_dir, single_file=single_file)
    if progress_callback:
        for p in macho_files:
            progress_callback(str(p))

    findings: list[Finding] = []
    findings.extend(_tool_gap_findings(target_dir))

    def _phase(name: str, func):
        try:
            findings.extend(func())
        except Exception as e:
            if error_callback:
                error_callback(f"macos module {name} phase failed: {e}")

    if single_file is not None:
        _phase("application-discovery", lambda: _single_file_discovery(single_file, macho_files))
        _phase("binary-analysis", lambda: _binary_analysis(macho_files))
        _phase("secrets", lambda: _config_and_secrets(target_dir, rules_dir, enable_entropy, single_file))
        _phase("update-mechanism", lambda: _update_mechanism_analysis(target_dir, macho_files))
        _phase("network-artifacts", lambda: _network_artifacts(findings))
        if not include_inventory:
            findings = [f for f in findings if INVENTORY_TAG not in f.tags]
        return findings

    _phase("application-discovery", lambda: _application_discovery(target_dir, macho_files))
    _phase("binary-analysis", lambda: _binary_analysis(macho_files))
    _phase("secrets", lambda: _config_and_secrets(target_dir, rules_dir, enable_entropy, single_file))
    _phase("certificate-analysis", lambda: _certificate_analysis(target_dir))
    _phase("update-mechanism", lambda: _update_mechanism_analysis(target_dir, macho_files))
    _phase("file-permissions", lambda: _file_permission_analysis(target_dir))
    _phase("third-party-libraries", lambda: _third_party_libraries(target_dir, macho_files))
    _phase("startup", lambda: _startup_items(target_dir))
    _phase("network-artifacts", lambda: _network_artifacts(findings))

    if not include_inventory:
        findings = [f for f in findings if INVENTORY_TAG not in f.tags]
    return findings
