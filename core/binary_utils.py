"""
Shared ELF (Linux) and Mach-O (macOS) parsing helpers.

Mirrors pe_utils.py's role for Windows PE files: magic-byte identification,
lightweight header parsing done in pure Python (no extra dependency), and
best-effort enrichment via system tools (`readelf`, `otool`, `codesign`)
when they're present on the analyst's PATH — the same "structural parse
always runs, deeper tool-assisted check is a bonus" pattern used by
signature_module.py for osslsigncode.

Used by linux_module.py and macos_module.py. Does not touch pe_utils.py or
any Windows-only code path.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import re
import plistlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --- ELF -------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

ELF_MACHINE = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x02: "SPARC",
}

ELF_TYPE = {
    1: "Relocatable",
    2: "Executable",
    3: "Shared object (PIE/.so)",
    4: "Core dump",
}


@dataclass
class ELFInfo:
    path: str
    is_valid_elf: bool = False
    is_64bit: bool = False
    machine: str = "unknown"
    elf_type: str = "unknown"
    is_pie: bool = False
    nx_stack: Optional[bool] = None  # GNU_STACK segment lacking PF_X
    needed_libraries: list[str] = field(default_factory=list)
    rpath_runpath: list[str] = field(default_factory=list)
    relro: str = "unknown"  # none/partial/full/unknown
    has_stack_canary: Optional[bool] = None
    fortify_symbols: list[str] = field(default_factory=list)
    stripped: Optional[bool] = None
    error: Optional[str] = None


def is_elf_file(path: Path) -> bool:
    """Verify genuine ELF magic (0x7f 'E' 'L' 'F') at file start."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == ELF_MAGIC
    except OSError:
        return False


def _readelf_available() -> bool:
    return shutil.which("readelf") is not None


def parse_elf(path: Path) -> ELFInfo:
    """
    Parse the fixed-size ELF header directly (arch, type, bitness) — always
    works, no external tool needed. NEEDED shared-library entries and
    RPATH/RUNPATH (dynamic-section contents) require walking the dynamic
    section; that part is delegated to `readelf -d` when available, since
    hand-rolling dynamic-section parsing adds real complexity for little
    benefit over a widely-available, well-tested system tool.
    """
    info = ELFInfo(path=str(path))
    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError as e:
        info.error = f"Could not read file: {e}"
        return info

    if len(header) < 20 or header[:4] != ELF_MAGIC:
        info.error = "Not a valid ELF file"
        return info

    info.is_valid_elf = True
    ei_class = header[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = header[5]   # 1 = little-endian, 2 = big-endian
    endian = "<" if ei_data == 1 else ">"
    info.is_64bit = ei_class == 2

    try:
        e_type = struct.unpack_from(endian + "H", header, 16)[0]
        e_machine = struct.unpack_from(endian + "H", header, 18)[0]
        info.elf_type = ELF_TYPE.get(e_type, f"unknown ({e_type})")
        info.machine = ELF_MACHINE.get(e_machine, f"unknown (0x{e_machine:x})")
        # ET_DYN (3) covers both real shared objects and PIE executables;
        # readelf/file distinguish via an ELF note or the .interp section,
        # but for our purposes "position independent" is the useful signal.
        info.is_pie = e_type == 3
    except struct.error as e:
        info.error = f"Malformed ELF header: {e}"
        return info

    if _readelf_available():
        try:
            out = subprocess.run(
                ["readelf", "-d", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines():
                if "NEEDED" in line and "[" in line:
                    lib = line.split("[", 1)[1].rstrip("]").strip()
                    info.needed_libraries.append(lib)
                elif "RPATH" in line or "RUNPATH" in line:
                    if "[" in line:
                        info.rpath_runpath.append(line.split("[", 1)[1].rstrip("]").strip())
                elif "BIND_NOW" in line:
                    info.relro = "full"
            # GNU_STACK executable-flag check (missing NX == exploit-relevant)
            hdrs = subprocess.run(
                ["readelf", "-lW", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in hdrs.splitlines():
                if "GNU_RELRO" in line and info.relro != "full":
                    info.relro = "partial"
                if "GNU_STACK" not in line:
                    continue
                # Flags column is a short token made only of R/W/E letters
                # (e.g. "RW " or "RWE"), separate from the numeric offset/
                # size/align columns — matching it precisely avoids the
                # previous fragile "'RWE' in line" substring check, which
                # could misfire against unrelated numeric columns.
                tokens = line.split()
                flag_tokens = [t for t in tokens if t and all(c in "RWE" for c in t)]
                if flag_tokens:
                    info.nx_stack = "E" not in flag_tokens[-1]
            syms = subprocess.run(
                ["readelf", "-sW", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            info.has_stack_canary = "__stack_chk_fail" in syms
            info.fortify_symbols = sorted(set(re.findall(r"\b([A-Za-z0-9_]+_chk)(?:@@|\s)", syms)))
            info.stripped = ".symtab" not in subprocess.run(
                ["readelf", "-SW", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            if info.relro == "unknown":
                info.relro = "none"
        except (subprocess.SubprocessError, OSError, IndexError):
            pass  # best-effort only; header-level info above is unaffected

    return info


# --- Mach-O ------------------------------------------------------------

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit (swapped)",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (swapped)",
    b"\xca\xfe\xba\xbe": "Mach-O fat/universal",
    b"\xbe\xba\xfe\xca": "Mach-O fat/universal (swapped)",
}


@dataclass
class MachOInfo:
    path: str
    is_valid_macho: bool = False
    variant: str = "unknown"
    linked_libraries: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    codesign_status: Optional[str] = None  # None = codesign unavailable/not run
    entitlements_xml: Optional[str] = None
    entitlements: dict = field(default_factory=dict)
    hardened_runtime: Optional[bool] = None
    notarized: Optional[bool] = None
    error: Optional[str] = None


def is_macho_file(path: Path) -> bool:
    """Verify genuine Mach-O / fat-binary magic bytes at file start."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic in MACHO_MAGICS
    except OSError:
        return False


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def parse_macho(path: Path) -> MachOInfo:
    """
    Identify the Mach-O variant from magic bytes (always works), then
    enrich with linked-library and code-signing info via `otool`/`codesign`
    when running on a machine that has them (typically macOS itself, or an
    analyst workstation with cctools installed). Falls back gracefully —
    the magic-byte identification and category-level findings never depend
    on these tools being present.
    """
    info = MachOInfo(path=str(path))
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError as e:
        info.error = f"Could not read file: {e}"
        return info

    if magic not in MACHO_MAGICS:
        info.error = "Not a valid Mach-O file"
        return info

    info.is_valid_macho = True
    info.variant = MACHO_MAGICS[magic]

    if _tool_available("otool"):
        try:
            out = subprocess.run(
                ["otool", "-L", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            for line in out.splitlines()[1:]:
                lib = line.strip().split(" (")[0].strip()
                if lib:
                    info.linked_libraries.append(lib)
            rpath_out = subprocess.run(
                ["otool", "-l", str(path)],
                capture_output=True, text=True, timeout=15,
            ).stdout
            lines = rpath_out.splitlines()
            for i, line in enumerate(lines):
                if "LC_RPATH" in line:
                    for follow in lines[i:i + 4]:
                        if "path " in follow:
                            info.rpaths.append(follow.strip().split("path ", 1)[1].split(" (")[0])
                            break
        except (subprocess.SubprocessError, OSError):
            pass

    if _tool_available("codesign"):
        try:
            proc = subprocess.run(
                ["codesign", "-dv", "--verbose=2", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            if "code object is not signed" in combined.lower():
                info.codesign_status = "unsigned"
            elif proc.returncode == 0:
                info.codesign_status = "signed"
            else:
                info.codesign_status = "unknown"
            info.hardened_runtime = "runtime" in combined.lower()
        except (subprocess.SubprocessError, OSError):
            pass

        try:
            ent = subprocess.run(
                ["codesign", "-d", "--entitlements", ":-", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if ent.returncode == 0 and ent.stdout.strip():
                info.entitlements_xml = ent.stdout
                try:
                    info.entitlements = plistlib.loads(ent.stdout.encode("utf-8"))
                except Exception:
                    info.entitlements = {}
        except (subprocess.SubprocessError, OSError):
            pass

    if _tool_available("spctl"):
        try:
            proc = subprocess.run(
                ["spctl", "-a", "-vv", "-t", "exec", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
            lower = combined.lower()
            if "notarized" in lower:
                info.notarized = True
            elif "accepted" in lower or "rejected" in lower:
                info.notarized = False
        except (subprocess.SubprocessError, OSError):
            pass

    return info
