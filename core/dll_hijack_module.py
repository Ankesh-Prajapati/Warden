"""
Module 2 — DLL Hijacking Detection (static analysis).

Covers, per the project spec:
  - PE import table enumeration (which DLLs each binary depends on)
  - DLL search order exposure: binaries that call LoadLibrary(Ex) without
    any safe-loading API (SetDllDirectory, SetDefaultDllDirectories,
    AddDllDirectory) are vulnerable to search-order planting
  - Unbundled DLL import indicators: imports not matched to the known system
    DLL catalog or application bundle, without assuming the target OS lacks
    them or that the loader can be hijacked
  - Writable install/working directories (classic hijack precondition)
  - Unquoted service path issues in Windows service binPaths (same
    vulnerability class, cheap to check via .reg exports or a services-file)

Static analysis only — no runtime loader tracing, no actual hijack payloads.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

import yaml

from core.fs_walk import check_permissive_permissions, find_pe_files
from core.models import Finding, Severity
from core.pe_utils import PEInfo, parse_pe

# APIs that, if present, indicate the binary takes some control over DLL
# search order/resolution rather than relying on default (unsafe) behavior.
# Note: For loadlibraryex*, we'd need to check flags to be truly safe,
# but for now we treat presence as a weaker positive signal.
SAFE_LOADING_APIS = {
    "setdlldirectorya", "setdlldirectoryw",
    "setdefaultdlldirectories", "adddlldirectory",
    "loadlibraryexa", "loadlibraryexw",  # only "safe" if flags are used, but
    # detecting actual flag values requires deeper disasm; presence is a
    # a weaker positive signal noted as such in the finding description.
}

# Import functions that indicate dynamic DLL loading is happening at all.
LOAD_LIBRARY_APIS = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}

_SYSTEM_DLLS_PATH = Path(__file__).resolve().parent.parent / "rules" / "system_dlls.yaml"


def _load_known_system_dlls(path: Path | None = None) -> set[str]:
    path = path or _SYSTEM_DLLS_PATH
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {d.lower() for d in data.get("known_system_dlls", [])}


@dataclass
class ServiceEntry:
    name: str
    image_path: str
    source: str  # file it was found in


def _build_local_dll_inventory(target_dir: Path, single_file: Path | None = None) -> set[str]:
    """Lowercased filenames of every DLL physically present under target_dir.

    When `single_file` is set (a single-EXE scan), this is scoped to just
    that file's own directory (non-recursive) rather than the whole tree —
    enough to check for sibling DLLs relevant to that one binary's hijack
    surface, without pulling unrelated files into the analysis."""
    if single_file is not None:
        return {p.name.lower() for p in Path(single_file).parent.glob("*.dll") if not p.is_symlink()}
    return {p.name.lower() for p in target_dir.rglob("*.dll") if not p.is_symlink()}


# ---------------------------------------------------------------------------
# Unquoted service path detection
# ---------------------------------------------------------------------------

_EXE_PATH_RE = re.compile(r'^(.*?\.exe)(.*)$', re.IGNORECASE)


def _is_unquoted_vulnerable(image_path: str) -> bool:
    """
    Classic unquoted service path check: if the executable portion of the
    path is not wrapped in quotes AND contains a space AND contains at
    least one subdirectory (i.e. isn't just a bare filename), the service
    control manager will try each space-delimited prefix as a candidate
    executable, allowing a planted binary to run with the service's
    privileges.
    """
    stripped = image_path.strip()
    if stripped.startswith('"'):
        return False

    m = _EXE_PATH_RE.match(stripped)
    if not m:
        return False

    exe_part = m.group(1)
    if " " not in exe_part:
        return False
    if "\\" not in exe_part and "/" not in exe_part:
        return False  # bare filename, no directory traversal possible

    return True


def _unquoted_candidates(image_path: str) -> list[str]:
    """The executables the SCM tries for an unquoted path, in order:
    "C:\\Program Files\\Acme Soft\\svc.exe" -> C:\\Program.exe, C:\\Program Files\\Acme.exe."""
    exe = _EXE_PATH_RE.match(image_path.strip()).group(1)
    parts = exe.split(" ")
    return [" ".join(parts[:i]) + ".exe" for i in range(1, len(parts))]


def parse_services_from_reg_text(text: str, source_name: str) -> list[ServiceEntry]:
    """
    Parse a Windows .reg export for service ImagePath values.

    Handles the standard `regedit /e` export format:
        [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SomeService]
        "ImagePath"="C:\\\\Program Files\\\\App\\\\svc.exe"

    ImagePath is usually REG_EXPAND_SZ, which regedit exports as
    `"ImagePath"=hex(2):43,00,3a,00,...` (UTF-16LE bytes, wrapped across
    lines with a trailing backslash) — those must be decoded, not read as
    text. REG_SZ values escape quotes, e.g. `"\\"C:\\\\Program Files\\\\x.exe\\""`.
    """
    entries: list[ServiceEntry] = []
    current_service = None

    key_re = re.compile(r"\[.*\\Services\\([^\\\]]+)\]", re.IGNORECASE)
    sz_re = re.compile(r'"ImagePath"\s*=\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
    hex_re = re.compile(r'"ImagePath"\s*=\s*hex\(2\):([0-9a-f,\s]*)', re.IGNORECASE)

    # Join "\"-continued lines (hex values span many physical lines).
    logical_lines = re.sub(r"\\\r?\n\s*", "", text).splitlines()

    for line in logical_lines:
        key_match = key_re.search(line)
        if key_match:
            current_service = key_match.group(1)
            continue
        if not current_service:
            continue
        raw_path = None
        if m := sz_re.search(line):
            raw_path = re.sub(r"\\(.)", r"\1", m.group(1))  # unescape \\ and \"
        elif m := hex_re.search(line):
            try:
                data = bytes(int(b, 16) for b in m.group(1).replace(" ", "").split(",") if b)
                raw_path = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
            except ValueError:
                raw_path = None
        if raw_path:
            entries.append(ServiceEntry(name=current_service, image_path=raw_path, source=source_name))
            current_service = None  # one ImagePath per service block expected

    return entries


def parse_services_from_sc_query_text(text: str, source_name: str) -> list[ServiceEntry]:
    """
    Parse plaintext output pasted from `sc query` / `wmic service get
    name,pathname` / `Get-WmiObject Win32_Service`. Best-effort: looks for
    lines containing a drive-letter path ending in .exe (with optional args).
    """
    entries: list[ServiceEntry] = []
    # Capture an optional leading quote too: dropping it made every properly
    # quoted path ("C:\Program Files\...\svc.exe") look unquoted.
    path_re = re.compile(r'("?[A-Za-z]:\\[^\r\n]*?\.exe\b[^\r\n]*)', re.IGNORECASE)
    # Anchored: unanchored, "Name" also matched inside "BINARY_PATH_NAME :".
    name_re = re.compile(r'^\s*(?:SERVICE_NAME|Name)\s*[:=]\s*(\S+)', re.IGNORECASE)

    current_name = "unknown-service"
    for line in text.splitlines():
        name_match = name_re.search(line)
        if name_match:
            current_name = name_match.group(1)
        path_match = path_re.search(line)
        if path_match:
            entries.append(
                ServiceEntry(name=current_name, image_path=path_match.group(1).strip(), source=source_name)
            )

    return entries


def _collect_service_entries(
    target_dir: Path, services_file: Path | None, single_file: Path | None = None
) -> list[ServiceEntry]:
    entries: list[ServiceEntry] = []

    # In single-EXE scope, there's no folder tree to pull .reg exports from —
    # only the optional explicit services_file (if provided) applies.
    reg_candidates = [] if single_file is not None else [
        p for p in target_dir.rglob("*.reg") if not p.is_symlink()
    ]

    for reg_path in reg_candidates:
        text = None
        try:
            raw = reg_path.read_bytes()
        except OSError:
            continue

        # Real `regedit /e` exports are UTF-16 with a BOM; some tools/analysts
        # produce plain UTF-8 .reg-style exports instead. Try both.
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            try:
                text = raw.decode("utf-16", errors="ignore")
            except UnicodeError:
                text = None
        if text is None:
            text = raw.decode("utf-8", errors="ignore")

        entries.extend(parse_services_from_reg_text(text, str(reg_path)))

    if services_file:
        services_file = Path(services_file)
        try:
            text = services_file.read_text(encoding="utf-8", errors="ignore")
            entries.extend(parse_services_from_sc_query_text(text, str(services_file)))
        except OSError:
            pass

    return entries


def _service_path_findings(entries: list[ServiceEntry]) -> list[Finding]:
    findings: list[Finding] = []
    for entry in entries:
        if _is_unquoted_vulnerable(entry.image_path):
            candidates = _unquoted_candidates(entry.image_path)
            candidate_dirs = list(dict.fromkeys(str(PureWindowsPath(c).parent) for c in candidates))
            findings.append(
                Finding(
                    module="dll_hijack",
                    rule_id="unquoted-service-path",
                    title=f"Unquoted service path — {entry.name}",
                    severity=Severity.HIGH,
                    file_path=entry.source,
                    evidence=entry.image_path,
                    description=(
                        f"Service '{entry.name}' has an unquoted ImagePath containing "
                        f"spaces. The Windows Service Control Manager will attempt each "
                        f"space-delimited path segment as a candidate executable, "
                        f"allowing a local attacker who can write to one of those "
                        f"parent paths to plant a malicious binary that runs with "
                        f"the service's privileges (often SYSTEM)."
                    ),
                    remediation=(
                        'Wrap the service ImagePath in double quotes, e.g. '
                        '"C:\\Program Files\\App\\svc.exe" -k netsvcs, and audit '
                        'write permissions on every parent directory in the path.'
                    ),
                    tags=["dll-hijack", "unquoted-path", "service"],
                    confidence="High",
                    poc=(
                        f"1. Confirm the vulnerable ImagePath directly:\n"
                        f"     reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{entry.name}\" /v ImagePath\n"
                        f"   (or inspect the registry export at {entry.source})\n"
                        f"   Expected value (unquoted): {entry.image_path}\n\n"
                        f"2. For this exact path the SCM tries these executables, in order, "
                        f"before the real one:\n"
                        + "".join(f"     {c}\n" for c in candidates)
                        + "   Check write access to each candidate's parent directory:\n"
                        # Quote only when needed: icacls "C:\" parses \" as an escaped quote.
                        + "".join(f"     icacls {chr(34) + d + chr(34) if ' ' in d else d}\n" for d in candidate_dirs)
                        + f"\n3. If a low-privileged account has write access to any of those "
                        f"directories, place a benign proof-of-concept binary (e.g. one that "
                        f"writes to a log file) at the matching candidate path, e.g. "
                        f"'{candidates[-1]}'.\n\n"
                        f"4. Restart the service (requires appropriate rights, or wait for a "
                        f"scheduled restart/reboot) and confirm the planted binary executed:\n"
                        f"     net stop {entry.name} ; net start {entry.name}\n"
                        f"   Verify via the PoC binary's log output or Process Monitor/"
                        f"Process Explorer showing the planted binary running under the "
                        f"service's account (often SYSTEM)."
                    ),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# PE-based hijack risk analysis
# ---------------------------------------------------------------------------

def _search_order_finding(pe_path: Path, pe_info: PEInfo) -> Finding | None:
    """Flag binaries that dynamically load libraries without safe-loading APIs."""
    all_funcs = {
        fn.lower()
        for funcs in pe_info.imported_functions.values()
        for fn in funcs
    }

    uses_loadlibrary = bool(all_funcs & LOAD_LIBRARY_APIS)
    # LoadLibraryEx presence counts as "may be safe": verifying its flags
    # would need disassembly of each call site.
    uses_safe_api = bool(all_funcs & SAFE_LOADING_APIS)

    if uses_loadlibrary and not uses_safe_api:
        return Finding(
            module="dll_hijack",
            rule_id="dll-search-order-exposure",
            title="Dynamic library loading without safe search-order controls",
            # A DLL inherits its host process's search order (e.g. the
            # installer's SetDefaultDllDirectories), so its imports alone are weak.
            severity=Severity.LOW if pe_info.is_dll else Severity.MEDIUM,
            file_path=str(pe_path),
            evidence="Imports LoadLibrary(A/W) but no evidence of safe search-order controls detected",
            description=(
                "This binary dynamically loads libraries at runtime but shows no "
                "evidence of restricting the DLL search order (e.g. via "
                "SetDllDirectory, SetDefaultDllDirectories, AddDllDirectory, or "
                "LoadLibraryEx with safe flags). By default, Windows' DLL search order "
                "can include the current working directory and other attacker-influenceable "
                "locations ahead of System32, depending on how the DLL is loaded and "
                "OS version/mitigations."
            ),
            remediation=(
                "Call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) early "
                "in the application, use LoadLibraryEx with LOAD_LIBRARY_SEARCH_SYSTEM32 "
                "flag, use fully-qualified paths when loading DLLs, "
                "and avoid loading libraries by bare name from an attacker-writable "
                "working directory."
            ),
            tags=["dll-hijack", "search-order"],
            confidence="Medium",
            poc=(
                "1. Review the PE import table and disassemble the call sites that "
                "invoke dynamic loading. Confirm the DLL name, LoadLibrary variant, "
                "and flags or path supplied at each call site.\n"
                "2. Review the relevant Windows loader policy and directory ACLs for "
                "the supported OS and launch configuration. Imports alone do not "
                "establish which directories are searched or that an attacker can "
                "write to one of them.\n"
                "3. Do not modify or run the scanned application with a planted DLL. "
                "Any runtime loader validation must use a deliberately isolated, "
                "authorized lab fixture."
            ),
        )
    return None


def _phantom_dll_findings(
    pe_path: Path,
    pe_info: PEInfo,
    known_system_dlls: set[str],
    local_dll_inventory: set[str],
) -> list[Finding]:
    findings: list[Finding] = []

    for dll_name in pe_info.imported_dlls:
        lname = dll_name.lower()
        # Check if the DLL is a known system DLL (exact or wildcard match)
        is_known_system = False
        for pattern in known_system_dlls:
            if pattern.endswith('*'):
                if lname.startswith(pattern[:-1]):
                    is_known_system = True
                    break
            else:
                if lname == pattern:
                    is_known_system = True
                    break
        if is_known_system or lname in local_dll_inventory:
            continue  # resolves locally or is a known system DLL — not phantom (writable-dir risk covered separately)

        findings.append(
            Finding(
                module="dll_hijack",
                rule_id="phantom-dll-import",
                title=f"Unbundled DLL import: {dll_name}",
                severity=Severity.INFO,
                file_path=str(pe_path),
                evidence=(
                    f"Imports '{dll_name}', not present in the scanned application bundle "
                    "or the known system-DLL catalog"
                ),
                description=(
                    f"'{dll_name}' is imported by this binary but was not found "
                    "inside the scanned application bundle or the conservative "
                    "known-system-DLL catalog. A static bundle scan cannot "
                    "determine whether the target Windows installation provides "
                    "this dependency, or whether its loader resolution is unsafe. "
                    "This is an unbundled dependency indicator, not evidence of "
                    "a missing runtime DLL or a confirmed hijack."
                ),
                remediation=(
                    "Check the vendor's dependency manifest and supported Windows "
                    "versions. Validate the dependency's trusted installation "
                    "source and actual load path from authorized system telemetry; "
                    "do not infer target-system absence from its absence in the "
                    "application bundle."
                ),
                tags=["dll-import", "external-dependency"],
                confidence="High",
                poc=(
                    "Static verification:\n"
                    f"  1. Confirm '{dll_name}' in the PE import table with "
                    "dumpbin /imports or a PE inspection tool.\n"
                    "  2. Check the vendor's package/dependency manifest and "
                    "documentation for supported Windows releases.\n"
                    "  3. Do not treat absence from this application's directory "
                    "as absence from the target OS, and do not plant or replace "
                    "a DLL to validate this static indicator. If loader behavior "
                    "must be studied, use a deliberately isolated, authorized "
                    "lab fixture and observe load paths without modifying the "
                    "application or system."
                ),
            )
        )

    return findings


def _writable_directory_finding(pe_path: Path) -> Finding | None:
    perm_info = check_permissive_permissions(pe_path.parent)
    if perm_info.get("world_writable"):
        return Finding(
            module="dll_hijack",
            rule_id="writable-binary-directory",
            title="World-writable directory containing application binary",
            severity=Severity.HIGH,
            file_path=str(pe_path.parent),
            evidence="Directory permission bits include world-write (o+w)",
            description=(
                f"The directory containing '{pe_path.name}' is writable by any "
                f"local user. Combined with any DLL search-order exposure or "
                f"phantom DLL import, this allows a low-privileged local "
                f"attacker to plant a malicious DLL or replace the binary itself."
            ),
            remediation=(
                "Restrict write access on the application's install directory "
                "to administrators and the application's own service account only."
            ),
            tags=["dll-hijack", "permissions"],
            confidence="Medium",
            poc=(
                f"1. Review the directory ACL without modifying it:\n"
                f"     icacls \"{pe_path.parent}\"\n"
                f"   Identify which principals have write or modify access and "
                f"compare them with the approved installation baseline.\n\n"
                f"2. This static permission observation does not establish that "
                f"an untrusted user can exploit a DLL search path or replace a "
                f"loaded component. Do not write files or plant DLLs in the "
                f"application directory. If write behavior itself needs testing, "
                f"use a separate, deliberately isolated, authorized lab fixture."
            ),
        )
    return None


def run(
    target_dir: str | Path,
    services_file: str | Path | None = None,
    system_dlls_path: str | Path | None = None,
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
) -> list[Finding]:
    """
    Entry point for Module 2. Statically analyzes every PE file under
    target_dir for DLL hijacking risk indicators, plus scans for unquoted
    service paths from .reg exports and/or an optional services-file.

    If `single_file` is given, analysis is restricted to that one PE file
    (plus its own directory's DLL inventory for hijack-surface context)
    instead of every PE file under target_dir.
    """
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None
    known_system_dlls = _load_known_system_dlls(Path(system_dlls_path) if system_dlls_path else None)
    local_dll_inventory = _build_local_dll_inventory(target_dir, single_file=single_file)

    all_findings: list[Finding] = []
    seen_fingerprints: set[str] = set()

    def _add(findings: list[Finding | None]):
        for f in findings:
            if f is None:
                continue
            fp = f.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(f)

    # --- Per-binary analysis ---
    flagged_writable_dirs: set[str] = set()

    for pe_path in find_pe_files(target_dir, single_file=single_file):
        if progress_callback:
            progress_callback(str(pe_path))

        try:
            pe_info = parse_pe(pe_path)
            if not pe_info.is_valid_pe:
                continue

            _add([_search_order_finding(pe_path, pe_info)])
            _add(_phantom_dll_findings(pe_path, pe_info, known_system_dlls, local_dll_inventory))

            parent_key = str(pe_path.parent)
            if parent_key not in flagged_writable_dirs:
                wf = _writable_directory_finding(pe_path)
                if wf:
                    _add([wf])
                    flagged_writable_dirs.add(parent_key)
        except Exception as e:
            if error_callback:
                error_callback(f"dll_hijack: skipped '{pe_path}' after error: {e}")
            continue

    # --- Service path analysis ---
    service_entries = _collect_service_entries(
        target_dir, Path(services_file) if services_file else None, single_file=single_file
    )
    _add(_service_path_findings(service_entries))

    return all_findings
