"""
Module 2 — DLL Hijacking Detection (static analysis).

Covers, per the project spec:
  - PE import table enumeration (which DLLs each binary depends on)
  - DLL search order exposure: binaries that call LoadLibrary(Ex) without
    any safe-loading API (SetDllDirectory, SetDefaultDllDirectories,
    AddDllDirectory) are vulnerable to search-order planting
  - Phantom DLL hijacking: imports that resolve to neither a known Windows
    system DLL nor a file present in the app's own directory tree — those
    are plantable by an attacker who can write anywhere in the search path
  - Writable install/working directories (classic hijack precondition)
  - Unquoted service path issues in Windows service binPaths (same
    vulnerability class, cheap to check via .reg exports or a services-file)

Static analysis only — no runtime loader tracing, no actual hijack payloads.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from core.fs_walk import check_permissive_permissions, find_pe_files
from core.models import Finding, Severity
from core.pe_utils import PEInfo, is_pe_file, parse_pe

# APIs that, if present, indicate the binary takes some control over DLL
# search order/resolution rather than relying on default (unsafe) behavior.
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


def parse_services_from_reg_text(text: str, source_name: str) -> list[ServiceEntry]:
    """
    Parse a Windows .reg export for service ImagePath values.

    Handles the standard `regedit /e` export format:
        [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SomeService]
        "ImagePath"="C:\\\\Program Files\\\\App\\\\svc.exe"
    """
    entries: list[ServiceEntry] = []
    current_service = None

    key_re = re.compile(r"\[.*\\Services\\([^\\\]]+)\]", re.IGNORECASE)
    imagepath_re = re.compile(r'"ImagePath"\s*=\s*(?:hex\(2\):)?"?([^"\r\n]+)"?', re.IGNORECASE)

    for line in text.splitlines():
        key_match = key_re.search(line)
        if key_match:
            current_service = key_match.group(1)
            continue
        img_match = imagepath_re.search(line)
        if img_match and current_service:
            raw_path = img_match.group(1).replace("\\\\", "\\")
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
    path_re = re.compile(r'([A-Za-z]:\\[^\r\n"]*?\.exe[^\r\n"]*)', re.IGNORECASE)
    name_re = re.compile(r'(?:SERVICE_NAME|Name)\s*[:=]\s*(\S+)', re.IGNORECASE)

    current_name = "unknown-service"
    for line in text.splitlines():
        name_match = name_re.search(line)
        if name_match:
            current_name = name_match.group(1)
        path_match = path_re.search(line)
        if path_match:
            entries.append(
                ServiceEntry(name=current_name, image_path=path_match.group(1), source=source_name)
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
                        f"   (or inspect the registry export at {entry.source})\n\n"
                        f"2. Identify a writable parent directory in the unquoted path. For "
                        f"path '{entry.image_path}', the SCM will try, in order, e.g.:\n"
                        f"     C:\\Program.exe\n"
                        f"     C:\\Program Files\\Vuln.exe\n"
                        f"     C:\\Program Files\\Vuln App\\svc.exe\n"
                        f"   Check write access to each candidate parent directory:\n"
                        f"     icacls \"C:\\Program Files\"\n"
                        f"     icacls \"C:\\Program Files\\Vuln App\"\n\n"
                        f"3. If a low-privileged account has write access to any candidate "
                        f"path, place a proof-of-concept binary there (e.g. a benign binary "
                        f"that writes to a log file) named to match the vulnerable prefix, "
                        f"e.g. 'C:\\Program Files\\Vuln.exe'.\n\n"
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
    uses_safe_api = bool(all_funcs & SAFE_LOADING_APIS)

    if uses_loadlibrary and not uses_safe_api:
        return Finding(
            module="dll_hijack",
            rule_id="dll-search-order-exposure",
            title="Dynamic library loading without safe search-order controls",
            severity=Severity.MEDIUM,
            file_path=str(pe_path),
            evidence="Imports LoadLibrary(A/W) but no SetDllDirectory/SetDefaultDllDirectories/AddDllDirectory call detected",
            description=(
                "This binary dynamically loads libraries at runtime but shows no "
                "evidence of restricting the DLL search order (e.g. via "
                "SetDllDirectory or SetDefaultDllDirectories). By default, Windows' "
                "DLL search order can include the current working directory and "
                "other attacker-influenceable locations ahead of System32, "
                "depending on how the DLL is loaded and OS version/mitigations."
            ),
            remediation=(
                "Call SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) early "
                "in the application, use fully-qualified paths when loading DLLs, "
                "and avoid loading libraries by bare name from an attacker-writable "
                "working directory."
            ),
            tags=["dll-hijack", "search-order"],
            confidence="Medium",
            poc=(
                f"1. Confirm the imports directly with a PE inspection tool:\n"
                f"     Windows: dumpbin /imports \"{pe_path}\"   (or open in CFF Explorer / PE-bear)\n"
                f"     Linux:   python3 -c \"import pefile; pe=pefile.PE(r'{pe_path}'); "
                f"[print(e.dll) for e in pe.DIRECTORY_ENTRY_IMPORT]\"\n"
                f"   Confirm LoadLibrary(A/W) is imported and no SetDllDirectory/"
                f"SetDefaultDllDirectories/AddDllDirectory call is present.\n\n"
                f"2. Identify a DLL this binary loads by bare name (via Process Monitor "
                f"with a 'Load Image' filter while running the binary from a writable "
                f"working directory):\n"
                f"     procmon.exe  (filter: Process Name is \"{Path(pe_path).name}\", "
                f"Operation is \"Load Image\", Result is \"NAME NOT FOUND\")\n\n"
                f"3. For any DLL Procmon shows being searched for in the current working "
                f"directory (and not found there), place a proof-of-concept DLL with that "
                f"exact name in the working directory used to launch the application. A "
                f"minimal PoC DLL just needs a DllMain that writes to a log file on load.\n\n"
                f"4. Re-run the application from that working directory and confirm the "
                f"planted DLL's DllMain executed (check the PoC log file), demonstrating "
                f"arbitrary code execution in this process's context via search-order "
                f"hijacking."
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
        if lname in known_system_dlls:
            continue
        if lname in local_dll_inventory:
            continue  # resolves locally — not phantom (writable-dir risk covered separately)

        findings.append(
            Finding(
                module="dll_hijack",
                rule_id="phantom-dll-import",
                title=f"Phantom/unresolved DLL import: {dll_name}",
                severity=Severity.HIGH,
                file_path=str(pe_path),
                evidence=f"Imports '{dll_name}', not found in app directory tree or known-system-DLL list",
                description=(
                    f"'{dll_name}' is imported by this binary but is neither a "
                    f"recognized Windows system DLL nor present anywhere in the "
                    f"scanned application directory. If this DLL is genuinely "
                    f"missing at runtime, the default DLL search order will let "
                    f"an attacker plant a malicious DLL with this name in a "
                    f"searched directory (application directory, current working "
                    f"directory, or PATH) to achieve code execution in this "
                    f"process's context."
                ),
                remediation=(
                    "Confirm whether this DLL is expected to be present on the "
                    "target system. If so, verify it's installed with correct "
                    "permissions from a trusted source; if it's an optional/"
                    "plugin dependency, load it via a fully-qualified path rather "
                    "than relying on search order."
                ),
                tags=["dll-hijack", "phantom-dll"],
                confidence="Medium",  # our known-system-DLL list isn't exhaustive
                poc=(
                    f"1. Confirm the import is genuinely unresolved on a real target "
                    f"install (not just missing from this static analysis machine):\n"
                    f"     Copy the application to a clean Windows VM matching the "
                    f"target's OS build, then run:\n"
                    f"     Process Monitor (procmon.exe) filtered to Process Name = "
                    f"\"{Path(pe_path).name}\", Operation = \"Load Image\", and look for "
                    f"a \"NAME NOT FOUND\" result for '{dll_name}'.\n\n"
                    f"2. If confirmed missing, build a minimal proof-of-concept DLL "
                    f"named exactly '{dll_name}' exporting a DllMain that writes a "
                    f"marker to a log file (e.g. using a template PoC DLL project or "
                    f"`x86_64-w64-mingw32-gcc -shared -o {dll_name} poc.c`).\n\n"
                    f"3. Place the PoC DLL in a directory searched before the location "
                    f"where the real DLL (if any) would legitimately reside — typically "
                    f"the application's own directory or the process's current working "
                    f"directory, per the default DLL search order.\n\n"
                    f"4. Launch '{Path(pe_path).name}' and confirm the PoC DLL's "
                    f"DllMain executed (check the marker log file) to demonstrate code "
                    f"execution in this process's context via the missing dependency."
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
                f"1. Confirm the permissive ACL directly:\n"
                f"     icacls \"{pe_path.parent}\"\n"
                f"   Look for an ACE granting (F), (M), or (W) to Everyone, "
                f"Authenticated Users, or Users (BUILTIN\\Users) without a "
                f"corresponding legitimate business reason.\n\n"
                f"2. From a low-privileged, non-administrator account, attempt to "
                f"write a test file into the directory:\n"
                f"     echo poc-write-test > \"{pe_path.parent}\\poc_write_test.txt\"\n\n"
                f"3. If the write succeeds, this confirms a local low-privileged "
                f"attacker can drop or replace files here. Combine with any "
                f"phantom-dll-import or dll-search-order-exposure finding above for "
                f"this same binary to demonstrate a full DLL-planting attack chain: "
                f"place a malicious DLL matching a missing/searched dependency name "
                f"in this directory, then trigger the application to load it.\n\n"
                f"4. Clean up the test file after confirming: "
                f"del \"{pe_path.parent}\\poc_write_test.txt\""
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
