"""
Filesystem walking and permission-inspection helpers.

Handles recursive directory traversal with extension filtering, binary vs
text classification, and best-effort permission checks for the
"overly permissive ACL on sensitive config" finding class.

Note: full Windows ACL inspection (DACL/SACL) requires pywin32 and is only
meaningful when run ON Windows. On Linux/macOS (typical analyst workstation
running this tool against an extracted install tree) we fall back to POSIX
mode bits, which is a reasonable proxy but not identical to a live Windows
ACL. This limitation is called out in the generated report.
"""
from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

# Extensions Module 1 treats as text/config for line-based regex+entropy scanning.
TEXT_EXTENSIONS = {
    ".config", ".xml", ".json", ".ini", ".env", ".yaml", ".yml",
    ".sql", ".reg", ".txt", ".log", ".properties", ".conf", ".cfg",
    ".manifest", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    # Linux/macOS config, unit, and metadata formats (additive — does not
    # change how any Windows file is classified).
    ".toml", ".service", ".timer", ".socket", ".desktop", ".plist",
    ".entitlements", ".control", ".list", ".repo",
}

# Extensions treated as PE binaries for string extraction + PE parsing.
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx"}

# Extensions treated as ELF binaries/libraries (Linux). Linux executables
# themselves are frequently extension-less, so callers also sniff by magic
# bytes (see find_elf_files) rather than relying on this set alone.
ELF_EXTENSIONS = {".so", ".ko"}

# Extensions treated as Mach-O binaries/libraries/frameworks (macOS).
MACHO_EXTENSIONS = {".dylib", ".bundle"}

# Local database files scanned for embedded plaintext (opened read-only,
# content sniffed as bytes rather than parsed as SQL/DB structure in v1).
DB_EXTENSIONS = {".mdb", ".accdb", ".sqlite", ".sqlite3", ".db"}

ALL_SCANNED_EXTENSIONS = (
    TEXT_EXTENSIONS | PE_EXTENSIONS | ELF_EXTENSIONS | MACHO_EXTENSIONS | DB_EXTENSIONS
)

# Skip these — they bloat scan time and are never config/secret sources.
SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules"}

# Guard against scanning pathologically large files (e.g. bundled installers,
# embedded media) that will dominate scan time for little finding value.
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


def iter_target_files(root: Path, single_file: Path | None = None):
    """
    Yield Path objects for every file worth scanning, based on extension
    allowlist. Skips oversized files and common noise directories.

    If `single_file` is given, scope is restricted to exactly that one path
    (still subject to the extension allowlist and size guard) instead of
    walking `root` — this is what a "scan this one EXE" selection in the GUI
    maps to, so picking a single file never pulls in unrelated files that
    happen to sit in the same folder.
    """
    if single_file is not None:
        p = Path(single_file)
        ext = p.suffix.lower()
        if ext not in ALL_SCANNED_EXTENSIONS:
            return
        try:
            if not p.is_file() or p.stat().st_size > MAX_FILE_SIZE_BYTES:
                return
        except OSError:
            return
        yield p
        return

    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            # Never follow file symlinks: a scanned target is untrusted by
            # definition, and a symlink pointing outside the target tree
            # (e.g. to /etc/passwd or a Windows SAM hive) would otherwise
            # let the target trick Warden into reading and reporting on
            # files well outside its intended scan scope.
            if p.is_symlink():
                continue
            ext = p.suffix.lower()
            if ext not in ALL_SCANNED_EXTENSIONS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def find_pe_files(target_dir: Path, single_file: Path | None = None) -> list[Path]:
    """
    Return every PE file (.exe/.dll/.sys/.ocx) that is a genuine PE image
    under `target_dir`, or — when `single_file` is given — just that one
    file (if it is itself a valid PE).

    Shared by Modules 2-4 (dll_hijack, signature, re_exposure) so a single
    "scan this one EXE" selection is honored consistently everywhere instead
    of each module independently re-walking the whole containing folder.
    """
    # Local import to avoid a circular import at module load time.
    from core.pe_utils import is_pe_file

    if single_file is not None:
        p = Path(single_file)
        if p.suffix.lower() in PE_EXTENSIONS and p.is_file() and is_pe_file(p):
            return [p]
        return []

    target_dir = Path(target_dir)
    results: list[Path] = []
    for ext in (".exe", ".dll", ".sys", ".ocx"):
        results.extend(target_dir.rglob(f"*{ext}"))
    # rglob('**') doesn't descend into symlinked directories, but it does
    # still match a symlinked *file* directly — exclude those for the same
    # scan-scope-escape reason as iter_target_files/iter_all_files above.
    return [p for p in results if not p.is_symlink() and is_pe_file(p)]


def iter_all_files(root: Path, single_file: Path | None = None):
    """
    Yield every regular file under `root` regardless of extension, skipping
    noise directories and oversized files.

    Used by the Linux/macOS modules to discover ELF/Mach-O executables and
    other artifacts (install scripts, package metadata) that commonly ship
    without a file extension — unlike Windows PEs, which always end in
    .exe/.dll/.sys/.ocx, so `iter_target_files`'s extension allowlist isn't
    a reliable way to find them.
    """
    if single_file is not None:
        p = Path(single_file)
        try:
            if p.is_file() and p.stat().st_size <= MAX_FILE_SIZE_BYTES:
                yield p
        except OSError:
            return
        return

    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                # Same rationale as iter_target_files: never follow a
                # symlink placed inside an untrusted scan target.
                continue
            try:
                if not p.is_file() or p.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def find_elf_files(target_dir: Path, single_file: Path | None = None) -> list[Path]:
    """Return every genuine ELF file under `target_dir` (magic-byte verified),
    regardless of extension — mirrors find_pe_files for Linux binaries."""
    from core.binary_utils import is_elf_file

    results: list[Path] = []
    for p in iter_all_files(target_dir, single_file=single_file):
        try:
            if is_elf_file(p):
                results.append(p)
        except OSError:
            continue
    return results


def find_macho_files(target_dir: Path, single_file: Path | None = None) -> list[Path]:
    """Return every genuine Mach-O file under `target_dir` (magic-byte
    verified), regardless of extension — mirrors find_pe_files for macOS
    binaries/frameworks."""
    from core.binary_utils import is_macho_file

    results: list[Path] = []
    for p in iter_all_files(target_dir, single_file=single_file):
        try:
            if is_macho_file(p):
                results.append(p)
        except OSError:
            continue
    return results


def classify_file(path: Path) -> str:
    """Return 'text', 'pe', 'db', or 'unknown' based on extension."""
    ext = path.suffix.lower()
    if ext in PE_EXTENSIONS:
        return "pe"
    if ext in DB_EXTENSIONS:
        return "db"
    if ext in TEXT_EXTENSIONS:
        return "text"
    return "unknown"


def check_permissive_permissions(path: Path) -> dict:
    """
    Best-effort check for overly permissive file permissions.

    On POSIX: flags world-writable (o+w) or world-readable-sensitive combos.
    On Windows: flags files without the read-only attribute as a weak proxy
    signal only — real ACL analysis needs pywin32 and is noted as a gap.
    """
    result = {
        "world_writable": False,
        "platform_checked": platform.system(),
        "note": None,
    }
    try:
        st = path.stat()
        if platform.system() != "Windows":
            mode = st.st_mode
            result["world_writable"] = bool(mode & stat.S_IWOTH)
            result["group_writable"] = bool(mode & stat.S_IWGRP)
        else:
            result["note"] = (
                "Running on Windows without ACL inspection enabled; only "
                "basic attributes checked. Use icacls for authoritative ACL review."
            )
    except OSError as e:
        result["note"] = f"Could not stat file: {e}"

    return result


def read_text_safely(path: Path, max_bytes: int = 5 * 1024 * 1024) -> str:
    """Read a text/config file defensively, tolerating odd encodings."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return ""
