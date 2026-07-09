"""
Module 4 — Reverse Engineering / Anti-Tamper Exposure.

Static indicators only — no dynamic/runtime analysis, no bypass tooling.
This module identifies *exposure*, not exploitation, per the project spec.

Covers:
  - Assembly / compiler-level exploit mitigations: ASLR (/DYNAMICBASE), DEP
    (/NXCOMPAT), SafeSEH (/SAFESEH, 32-bit only), Control Flow Guard
    (/GUARD:CF) — the "Assembly Security Analysis" checklist from thick-
    client methodology (equivalent to Get-PESecurity).
  - Packer detection via section entropy + known packer section-name
    signatures (UPX, Themida, VMProtect, etc.) — high entropy is also
    reported as an inverse signal (unpacked .NET/Java = easily decompilable).
  - .NET obfuscation check: detects whether a .NET assembly shows known
    obfuscator markers; flags "not obfuscated" when the binary appears to
    handle sensitive logic (license/crypto keywords) client-side with fully
    readable IL.
  - Embedded PDB / debug symbol path leakage.
  - Anti-debug API reference presence (maturity signal, not a bypass tool).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from core.models import Finding, Severity
from core.pe_utils import (
    MitigationInfo,
    PEInfo,
    extract_strings_from_bytes,
    get_security_mitigations,
    is_pe_file,
    parse_pe,
)

# Import functions whose presence signals anti-debug awareness. Presence is
# a maturity signal only — this module never generates bypass code.
ANTI_DEBUG_APIS = {
    "isdebuggerpresent", "checkremotedebuggerpresent",
    "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw",
}

# Keywords suggesting sensitive client-side logic — used only to decide
# whether "not obfuscated" is worth flagging (readable IL for a throwaway
# utility DLL is low-value noise; readable IL handling license/crypto logic
# is a real finding).
SENSITIVE_LOGIC_KEYWORDS = (
    "license", "activation", "serial", "unlock", "trial",
    "crypt", "decrypt", "encrypt", "aeskey", "rsakey",
)

_PACKER_SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "rules" / "packer_signatures.yaml"

# Section entropy above this is treated as likely packed/encrypted.
# (Shannon entropy per byte, max 8.0; legitimate compiled code sections
# typically sit well below 7.0, compressed/encrypted data usually >7.2.)
HIGH_SECTION_ENTROPY_THRESHOLD = 7.2


def _load_packer_signatures(path: Path | None = None) -> dict:
    path = path or _PACKER_SIGNATURES_PATH
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _find_pe_files(target_dir: Path) -> list[Path]:
    results = []
    for ext in (".exe", ".dll", ".sys", ".ocx"):
        results.extend(target_dir.rglob(f"*{ext}"))
    return [p for p in results if is_pe_file(p)]


# ---------------------------------------------------------------------------
# Assembly Security Analysis (ASLR / DEP / SafeSEH / CFG)
# ---------------------------------------------------------------------------

def _mitigation_findings(pe_path: Path, mit: MitigationInfo) -> list[Finding]:
    findings: list[Finding] = []
    if not mit.is_valid_pe:
        return findings

    bitness = "64-bit" if mit.is_64bit else "32-bit"

    if not mit.aslr_dynamic_base:
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="aslr-disabled",
                title="ASLR (Address Space Layout Randomization) not enabled",
                severity=Severity.HIGH,
                file_path=str(pe_path),
                evidence="OPTIONAL_HEADER.DllCharacteristics missing IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                description=(
                    "This binary was not compiled with /DYNAMICBASE, so its "
                    "modules load at a predictable base address on every "
                    "run. This significantly simplifies memory-corruption "
                    "exploitation (return-to-libc, ROP chain construction) "
                    "by removing the need to defeat address randomization."
                ),
                remediation="Recompile with the /DYNAMICBASE linker flag (enabled by default in modern MSVC; verify it hasn't been explicitly disabled).",
                poc=(
                    f"1. Confirm directly with PowerShell:\n"
                    f"     Import-Module .\\Get-PESecurity.psm1\n"
                    f"     Get-PESecurity -file \"{pe_path}\"\n"
                    f"   (ASLR column will show False/Disabled)\n\n"
                    f"2. Or inspect the raw flag with pefile:\n"
                    f"     python3 -c \"import pefile; pe=pefile.PE(r'{pe_path}'); "
                    f"print(bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40))\"\n\n"
                    f"3. Demonstrate impact: run the binary twice and compare its "
                    f"module base address in Process Hacker/System Informer "
                    f"(Properties > Memory) or via WinDbg's `lm` command. "
                    f"Identical base addresses across runs confirm ASLR is "
                    f"not in effect for this module, which is a precondition "
                    f"for reliable memory-corruption exploit development."
                ),
                tags=["re-exposure", "mitigation", "aslr"],
                confidence="High",
            )
        )

    if mit.is_64bit and mit.aslr_dynamic_base and not mit.aslr_high_entropy_va:
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="aslr-high-entropy-va-disabled",
                title="High-entropy ASLR not enabled (64-bit)",
                severity=Severity.MEDIUM,
                file_path=str(pe_path),
                evidence="64-bit binary missing IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
                description=(
                    "ASLR is enabled but without high-entropy virtual address "
                    "support, this 64-bit binary gets a smaller randomization "
                    "range than modern Windows can provide, somewhat easing "
                    "brute-force address-guessing attacks."
                ),
                remediation="Recompile with /HIGHENTROPYVA (default in current MSVC toolchains for 64-bit targets).",
                tags=["re-exposure", "mitigation", "aslr"],
                confidence="Medium",
            )
        )

    if not mit.dep_nx_compat:
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="dep-disabled",
                title="DEP/NX (Data Execution Prevention) not enabled",
                severity=Severity.HIGH,
                file_path=str(pe_path),
                evidence="OPTIONAL_HEADER.DllCharacteristics missing IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                description=(
                    "This binary was not compiled with /NXCOMPAT, meaning it "
                    "opts out of hardware DEP support. Combined with a memory-"
                    "corruption bug, this makes classic shellcode injection "
                    "into a data segment (stack/heap) directly executable."
                ),
                remediation="Recompile with the /NXCOMPAT linker flag (default in modern MSVC).",
                poc=(
                    f"1. Confirm directly:\n"
                    f"     python3 -c \"import pefile; pe=pefile.PE(r'{pe_path}'); "
                    f"print(bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100))\"\n\n"
                    f"2. Cross-check at runtime in Process Hacker/System Informer: "
                    f"select the running process > Properties > General tab > "
                    f"'DEP' should show 'Disabled' if the flag is truly not "
                    f"honored (Windows may still enforce system-wide DEP "
                    f"depending on policy — note both the binary flag and the "
                    f"runtime enforcement outcome as separate data points)."
                ),
                tags=["re-exposure", "mitigation", "dep"],
                confidence="High",
            )
        )

    if not mit.is_64bit and mit.safeseh_present is False:
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="safeseh-disabled",
                title="SafeSEH not enabled (32-bit binary)",
                severity=Severity.MEDIUM,
                file_path=str(pe_path),
                evidence="No populated SEHandlerTable in load config directory, or IMAGE_DLLCHARACTERISTICS_NO_SEH set",
                description=(
                    f"This {bitness} binary does not appear to have SafeSEH "
                    f"enabled, leaving structured exception handler chains "
                    f"unvalidated. Exploits that overwrite an SEH record can "
                    f"redirect execution without SafeSEH validating that the "
                    f"handler address is a registered, expected one."
                ),
                remediation="Recompile with the /SAFESEH linker flag (32-bit only; not applicable/needed for 64-bit targets, which use table-based SEH).",
                tags=["re-exposure", "mitigation", "safeseh"],
                confidence="Medium",
            )
        )

    if not mit.cfg_guard:
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="cfg-disabled",
                title="Control Flow Guard (CFG) not enabled",
                severity=Severity.MEDIUM,
                file_path=str(pe_path),
                evidence="OPTIONAL_HEADER.DllCharacteristics missing IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                description=(
                    "This binary was not compiled with /GUARD:CF, so indirect "
                    "call targets are not validated at runtime. This makes "
                    "ROP/JOP-style control-flow hijacking following a "
                    "memory-corruption bug comparatively easier to pull off."
                ),
                remediation="Recompile with the /GUARD:CF linker flag where toolchain and target OS support it.",
                tags=["re-exposure", "mitigation", "cfg"],
                confidence="Medium",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Packer detection
# ---------------------------------------------------------------------------

def _packer_findings(pe_path: Path, pe_info: PEInfo, signatures: dict) -> list[Finding]:
    findings: list[Finding] = []
    known_section_names = {s.lower() for s in signatures.get("packer_section_names", [])}

    matched_sections = [s for s in pe_info.sections if s["name"].lower() in known_section_names]
    high_entropy_sections = [s for s in pe_info.sections if s["entropy"] >= HIGH_SECTION_ENTROPY_THRESHOLD]

    if matched_sections:
        names = ", ".join(s["name"] for s in matched_sections)
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="known-packer-section-signature",
                title=f"Known packer/protector section signature detected ({names})",
                severity=Severity.MEDIUM,
                file_path=str(pe_path),
                evidence=f"Section name(s) matching known packer signatures: {names}",
                description=(
                    "This binary contains one or more PE sections whose "
                    "names match known packer/protector tools (e.g. UPX, "
                    "Themida, VMProtect, ASPack). Packed binaries resist "
                    "casual static analysis, which can be legitimate IP "
                    "protection but also complicates security review and "
                    "is sometimes used to evade signature-based AV/EDR "
                    "detection."
                ),
                remediation=(
                    "If packing is intentional for IP protection, ensure it "
                    "doesn't interfere with signature/integrity verification "
                    "(unpacked-at-runtime code should still be covered by "
                    "your update/signing process). If unexpected, investigate "
                    "why this binary is packed and whether it matches the "
                    "expected build output."
                ),
                tags=["re-exposure", "packer"],
                confidence="Medium",
            )
        )

    if high_entropy_sections and not matched_sections:
        names = ", ".join(f"{s['name']} ({s['entropy']})" for s in high_entropy_sections)
        findings.append(
            Finding(
                module="re_exposure",
                rule_id="high-entropy-section",
                title="High-entropy PE section (possible unrecognized packer/encryption)",
                severity=Severity.LOW,
                file_path=str(pe_path),
                evidence=f"Section(s) with entropy >= {HIGH_SECTION_ENTROPY_THRESHOLD}: {names}",
                description=(
                    "One or more sections show entropy consistent with "
                    "compression or encryption, but no known packer "
                    "signature matched. This can indicate a custom/unknown "
                    "packer, encrypted resources, or simply compressed "
                    "embedded assets (icons, installers) — manual review "
                    "recommended to distinguish these cases."
                ),
                remediation="Manually inspect the high-entropy section(s) to determine whether they contain packed code, encrypted data, or compressed assets.",
                tags=["re-exposure", "packer", "entropy"],
                confidence="Low",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# .NET obfuscation check
# ---------------------------------------------------------------------------

def _is_dotnet_assembly(pe_path: Path, pe_info: PEInfo) -> bool:
    return "mscoree.dll" in [d.lower() for d in pe_info.imported_dlls]


def _dotnet_obfuscation_finding(pe_path: Path, pe_info: PEInfo, signatures: dict) -> Finding | None:
    if not _is_dotnet_assembly(pe_path, pe_info):
        return None

    try:
        data = pe_path.read_bytes()
    except OSError:
        return None

    strings_with_offsets = extract_strings_from_bytes(data)
    joined = "\n".join(s for s, _ in strings_with_offsets)
    joined_lower = joined.lower()

    markers = signatures.get("dotnet_obfuscator_markers", [])
    matched_marker = next((m for m in markers if m.lower() in joined_lower), None)

    if matched_marker:
        return None  # obfuscated — no finding, this is the good case

    has_sensitive_logic = any(kw in joined_lower for kw in SENSITIVE_LOGIC_KEYWORDS)
    if not has_sensitive_logic:
        return None  # not obfuscated, but nothing sensitive detected either — low value noise

    matched_kw = next(kw for kw in SENSITIVE_LOGIC_KEYWORDS if kw in joined_lower)
    return Finding(
        module="re_exposure",
        rule_id="dotnet-not-obfuscated-sensitive-logic",
        title=".NET assembly handling sensitive logic without detected obfuscation",
        severity=Severity.MEDIUM,
        file_path=str(pe_path),
        evidence=f"No known obfuscator marker found; sensitive-logic keyword matched: '{matched_kw}'",
        description=(
            ".NET IL is trivially decompiled back to near-original source "
            "with tools like dnSpy or ILSpy. This assembly appears to "
            "reference license/crypto/activation logic (keyword match: "
            f"'{matched_kw}') but shows no marker of a common commercial "
            "obfuscator (ConfuserEx, Eazfuscator, .NET Reactor, etc.), "
            "meaning this logic is likely readable as close to source form."
        ),
        remediation=(
            "Apply a .NET obfuscator to assemblies containing licensing, "
            "activation, or cryptographic key-handling logic, and treat any "
            "client-side license/entitlement check as inherently bypassable "
            "regardless of obfuscation — enforce authoritative checks "
            "server-side where possible."
        ),
        poc=(
            f"1. Confirm directly by decompiling:\n"
            f"     Open \"{pe_path}\" in dnSpy or ILSpy.\n"
            f"     Navigate to the type/method referencing '{matched_kw}'-"
            f"related logic and confirm the decompiled C# is readable "
            f"(meaningful variable/method names, intact control flow) "
            f"rather than obfuscated (renamed to single letters, control-"
            f"flow flattened, strings encrypted).\n\n"
            f"2. If this handles license/activation checks, demonstrate "
            f"impact by identifying the boolean/branch that gates the "
            f"licensed feature and confirming it could be patched directly "
            f"in IL (e.g. with dnSpy's 'Edit Method' or a simple IL patcher) "
            f"to always return true — do this only in an isolated test "
            f"copy, never against a live licensing server."
        ),
        tags=["re-exposure", "dotnet", "obfuscation"],
        confidence="Medium",
    )


# ---------------------------------------------------------------------------
# PDB / debug symbol leakage
# ---------------------------------------------------------------------------

def _pdb_leak_finding(pe_path: Path, pe_info: PEInfo) -> Finding | None:
    if not pe_info.pdb_path:
        return None

    return Finding(
        module="re_exposure",
        rule_id="embedded-pdb-path-leak",
        title="Embedded PDB debug path leakage",
        severity=Severity.LOW,
        file_path=str(pe_path),
        evidence=f"PDB path: {pe_info.pdb_path}",
        description=(
            "This binary embeds a full path to its PDB debug symbol file, "
            "typically left over from an unstripped release build. This "
            "commonly leaks internal developer machine usernames, build "
            "server directory structure, or internal project naming "
            "conventions — minor but free reconnaissance information for "
            "an attacker profiling the target organization's build "
            "environment."
        ),
        remediation=(
            "Strip debug directory entries from release builds, or use "
            "/PDBALTPATH with a generic relative path so no internal "
            "filesystem information is embedded in shipped binaries."
        ),
        poc=(
            f"1. Confirm directly:\n"
            f"     dumpbin /headers \"{pe_path}\" | findstr /i pdb\n"
            f"   or with pefile:\n"
            f"     python3 -c \"import pefile; pe=pefile.PE(r'{pe_path}'); "
            f"pe.parse_data_directories(); print(pe.DIRECTORY_ENTRY_DEBUG[0].entry.PdbFileName)\"\n\n"
            f"2. Review the leaked path for anything organizationally "
            f"sensitive: '{pe_info.pdb_path}' — note the OS username, drive "
            f"layout, and any internal project/codename it reveals for the "
            f"client report."
        ),
        tags=["re-exposure", "pdb-leak", "recon"],
        confidence="High",
    )


# ---------------------------------------------------------------------------
# Anti-debug API presence (informational maturity signal)
# ---------------------------------------------------------------------------

def _anti_debug_finding(pe_path: Path, pe_info: PEInfo) -> Finding | None:
    all_funcs = {
        fn.lower()
        for funcs in pe_info.imported_functions.values()
        for fn in funcs
    }
    if all_funcs & ANTI_DEBUG_APIS:
        return None  # anti-debug awareness present — no finding needed

    return Finding(
        module="re_exposure",
        rule_id="no-anti-debug-apis-detected",
        title="No anti-debugging API references detected",
        severity=Severity.INFO,
        file_path=str(pe_path),
        evidence="No import of IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess/OutputDebugString found",
        description=(
            "This binary shows no evidence of anti-debugging checks. This "
            "is an exposure/maturity signal only — it means the binary can "
            "likely be attached to and analyzed with a standard debugger "
            "(x64dbg, WinDbg) without needing to defeat any anti-debug "
            "trick, which lowers the effort required for dynamic reverse "
            "engineering. This is informational, not a vulnerability in "
            "itself, and anti-debug measures are not a substitute for "
            "proper security controls."
        ),
        remediation=(
            "If runtime tamper-resistance is a business requirement for "
            "this binary (e.g. anti-cheat, DRM, licensing enforcement), "
            "consider standard anti-debug/anti-tamper techniques as one "
            "layer of defense — but do not rely on them as a primary "
            "security control, since they only raise analysis cost rather "
            "than prevent it."
        ),
        tags=["re-exposure", "anti-debug", "informational"],
        confidence="Low",
    )


def run(
    target_dir: str | Path,
    packer_signatures_path: str | Path | None = None,
    progress_callback=None,
) -> list[Finding]:
    """
    Entry point for Module 4. Statically analyzes every PE file under
    target_dir for exploit-mitigation exposure, packer/obfuscation
    indicators, PDB leakage, and anti-debug maturity signals.
    """
    target_dir = Path(target_dir)
    signatures = _load_packer_signatures(Path(packer_signatures_path) if packer_signatures_path else None)

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

    for pe_path in _find_pe_files(target_dir):
        if progress_callback:
            progress_callback(str(pe_path))

        pe_info = parse_pe(pe_path)
        if not pe_info.is_valid_pe:
            continue

        mit = get_security_mitigations(pe_path)
        _add(_mitigation_findings(pe_path, mit))
        _add(_packer_findings(pe_path, pe_info, signatures))
        _add([_dotnet_obfuscation_finding(pe_path, pe_info, signatures)])
        _add([_pdb_leak_finding(pe_path, pe_info)])
        _add([_anti_debug_finding(pe_path, pe_info)])

    return all_findings
