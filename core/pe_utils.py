"""
Shared PE (Portable Executable) parsing helpers, built on `pefile`.

Used by:
- secrets_module: extract embedded ASCII/UTF-16 strings from .exe/.dll for
  secret scanning
- dll_hijack_module (later): import table enumeration
- re_exposure_module (later): section entropy / packer signals, PDB path leaks

Kept in one place so every module parses each PE file only once per scan.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

# Minimum printable-run length to count as an extractable "string" — mirrors
# the default of the classic `strings` utility.
MIN_STRING_LEN = 6

_ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
# UTF-16LE strings: printable ASCII byte followed by a null byte, repeated.
_UTF16_STRING_RE = re.compile(
    rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN
)


@dataclass
class PEInfo:
    path: str
    is_valid_pe: bool
    is_dll: bool = False
    imported_dlls: list[str] = field(default_factory=list)
    imported_functions: dict = field(default_factory=dict)  # dll -> [funcs]
    has_delay_imports: bool = False
    sections: list[dict] = field(default_factory=list)  # name, entropy, size
    pdb_path: Optional[str] = None
    cert_directory_present: bool = False
    error: Optional[str] = None


def is_pe_file(path: Path) -> bool:
    """
    Verify this is a genuine PE image, not just any file that happens to
    start with the MZ magic bytes (the DOS stub header is only two bytes —
    plenty of non-PE files, truncated downloads, or renamed files can
    coincidentally start with 'MZ'). Confirms the e_lfanew pointer at
    offset 0x3C resolves to an actual "PE\\0\\0" signature before treating
    the file as a PE binary anywhere in the scan.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                return False
            e_lfanew = int.from_bytes(header[0x3C:0x40], "little")
            if e_lfanew <= 0 or e_lfanew > 16 * 1024 * 1024:
                return False  # sanity guard against a garbage/corrupt pointer
            f.seek(e_lfanew)
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def extract_strings_from_bytes(data: bytes, min_len: int = MIN_STRING_LEN) -> list[tuple[str, int]]:
    """
    Extract printable ASCII and UTF-16LE strings from raw bytes.

    Returns list of (string, byte_offset) tuples. This is the binary
    equivalent of the text-file line scanning done for config/source files,
    letting Module 1's rule engine run against binary-embedded strings too.
    """
    results: list[tuple[str, int]] = []

    for m in _ASCII_STRING_RE.finditer(data):
        results.append((m.group(0).decode("ascii", errors="ignore"), m.start()))

    for m in _UTF16_STRING_RE.finditer(data):
        try:
            decoded = m.group(0).decode("utf-16-le", errors="ignore")
        except UnicodeDecodeError:
            continue
        if len(decoded) >= min_len:
            results.append((decoded, m.start()))

    return results


def get_security_directory_bytes(path: Path) -> Optional[bytes]:
    """
    Read the raw WIN_CERTIFICATE table bytes referenced by the PE's
    IMAGE_DIRECTORY_ENTRY_SECURITY data directory.

    Unlike every other data directory, the security directory's
    VirtualAddress is a *file offset*, not an RVA — so this reads directly
    from the file rather than through pefile's RVA-mapped section data.
    Returns None if the file isn't a valid PE or has no security directory.
    """
    if pefile is None:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        offset, size = sec_dir.VirtualAddress, sec_dir.Size
        pe.close()
    except Exception:
        return None

    if not offset or not size:
        return None

    try:
        with open(path, "rb") as f:
            f.seek(offset)
            raw = f.read(size)
    except OSError:
        return None

    return raw if raw else None


def extract_pkcs7_from_win_certificate(raw: bytes) -> Optional[bytes]:
    """
    Strip the WIN_CERTIFICATE header (dwLength, wRevision, wCertificateType)
    from raw security-directory bytes to get the embedded PKCS#7 SignedData
    blob. Handles a chain of multiple WIN_CERTIFICATE entries by returning
    only the first (Authenticode uses a single entry in practice).
    """
    if len(raw) < 8:
        return None
    dw_length = int.from_bytes(raw[0:4], "little")
    # w_revision = raw[4:6]; w_certificate_type = raw[6:8]
    cert_data = raw[8:dw_length] if dw_length <= len(raw) else raw[8:]
    return cert_data if cert_data else None


# IMAGE_DLLCHARACTERISTICS flags relevant to exploit mitigations.
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040       # ASLR
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100          # DEP
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000           # Control Flow Guard


@dataclass
class MitigationInfo:
    path: str
    is_valid_pe: bool = False
    is_64bit: bool = False
    aslr_dynamic_base: bool = False
    aslr_high_entropy_va: bool = False   # only meaningful for 64-bit
    dep_nx_compat: bool = False
    no_seh: bool = False
    cfg_guard: bool = False
    safeseh_present: Optional[bool] = None  # only meaningful for 32-bit; None = N/A
    error: Optional[str] = None


def get_security_mitigations(path: Path) -> MitigationInfo:
    """
    Parse a PE's OPTIONAL_HEADER.DllCharacteristics and (for 32-bit binaries)
    its load config directory to determine which standard exploit
    mitigations are enabled: ASLR (/DYNAMICBASE), DEP (/NXCOMPAT), SafeSEH
    (/SAFESEH, 32-bit only), and Control Flow Guard (/GUARD:CF).
    """
    info = MitigationInfo(path=str(path))
    if pefile is None:
        info.error = "pefile module not installed"
        return info

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
        )
    except Exception as e:
        info.error = f"Failed to parse PE: {e}"
        return info

    info.is_valid_pe = True
    info.is_64bit = pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_AMD64", 0x8664)

    chars = pe.OPTIONAL_HEADER.DllCharacteristics
    info.aslr_dynamic_base = bool(chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    info.aslr_high_entropy_va = bool(chars & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
    info.dep_nx_compat = bool(chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    info.no_seh = bool(chars & IMAGE_DLLCHARACTERISTICS_NO_SEH)
    info.cfg_guard = bool(chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    if not info.is_64bit:
        # SafeSEH is signaled by a populated SEHandlerTable/Count in the load
        # config directory, and requires NO_SEH to NOT be set.
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                load_config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                handler_count = getattr(load_config, "SEHandlerCount", 0)
                info.safeseh_present = (handler_count > 0) and not info.no_seh
            else:
                # No load config directory at all: treat as SafeSEH absent
                # rather than "unknown" for 32-bit binaries, since modern
                # toolchains emit this directory when /SAFESEH is used.
                info.safeseh_present = False
        except Exception:
            info.safeseh_present = None  # genuinely couldn't determine

    pe.close()
    return info


def parse_pe(path: Path) -> PEInfo:
    """Parse a PE file for imports, sections, PDB path, and cert presence."""
    info = PEInfo(path=str(path), is_valid_pe=False)

    if pefile is None:
        info.error = "pefile module not installed"
        return info

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            ]
        )
    except Exception as e:  # pefile raises bare Exception subclasses
        info.error = f"Failed to parse PE: {e}"
        return info

    info.is_valid_pe = True
    info.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)  # IMAGE_FILE_DLL

    # --- Imports ---
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="ignore") if entry.dll else "?"
            info.imported_dlls.append(dll_name)
            funcs = [
                imp.name.decode("ascii", errors="ignore")
                for imp in entry.imports
                if imp.name
            ]
            info.imported_functions[dll_name] = funcs

    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        info.has_delay_imports = len(pe.DIRECTORY_ENTRY_DELAY_IMPORT) > 0
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="ignore") if entry.dll else "?"
            if dll_name not in info.imported_dlls:
                info.imported_dlls.append(dll_name)

    # --- Sections (entropy used later by re_exposure_module for packer detection) ---
    for section in pe.sections:
        try:
            name = section.Name.decode("ascii", errors="ignore").rstrip("\x00")
        except Exception:
            name = "?"
        info.sections.append(
            {
                "name": name,
                "entropy": round(section.get_entropy(), 3),
                "raw_size": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
            }
        )

    # --- PDB / debug path leakage ---
    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            try:
                dbg_data = dbg.entry
                if dbg_data and hasattr(dbg_data, "PdbFileName"):
                    raw = dbg_data.PdbFileName
                    if isinstance(raw, bytes):
                        info.pdb_path = raw.split(b"\x00", 1)[0].decode(
                            "utf-8", errors="ignore"
                        )
            except Exception:
                continue

    # --- Authenticode cert directory presence (full validation is Module 3's job) ---
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        info.cert_directory_present = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
    except Exception:
        pass

    pe.close()
    return info
