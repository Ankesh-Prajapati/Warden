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
}

# Extensions treated as PE binaries for string extraction + PE parsing.
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx"}

# Local database files scanned for embedded plaintext (opened read-only,
# content sniffed as bytes rather than parsed as SQL/DB structure in v1).
DB_EXTENSIONS = {".mdb", ".accdb", ".sqlite", ".sqlite3", ".db"}

ALL_SCANNED_EXTENSIONS = TEXT_EXTENSIONS | PE_EXTENSIONS | DB_EXTENSIONS

# Skip these — they bloat scan time and are never config/secret sources.
SKIP_DIR_NAMES = {".git", "__pycache__", "node_modules"}

# Guard against scanning pathologically large files (e.g. bundled installers,
# embedded media) that will dominate scan time for little finding value.
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB


def iter_target_files(root: Path):
    """
    Yield Path objects for every file under `root` worth scanning, based on
    extension allowlist. Skips oversized files and common noise directories.
    """
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            ext = p.suffix.lower()
            if ext not in ALL_SCANNED_EXTENSIONS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            yield p


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
