"""Client-facing path normalization for scan results."""
from __future__ import annotations

import ntpath
import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath


def _relative_path(path: str, root: str | Path | None) -> str:
    if not root:
        return path.replace("\\", "/")

    if PureWindowsPath(path).drive or PureWindowsPath(str(root)).drive:
        win_path = ntpath.normpath(path)
        win_root = ntpath.normpath(str(root))
        try:
            relative = ntpath.relpath(win_path, win_root)
        except ValueError:
            return PureWindowsPath(path).name
        if relative == ".." or relative.startswith(".." + ntpath.sep):
            return PureWindowsPath(path).name
        return relative.replace("\\", "/")

    try:
        relative = os.path.relpath(path, str(root))
    except ValueError:
        return PurePosixPath(path).name
    if relative == ".." or relative.startswith("../"):
        return PurePosixPath(path).name
    return relative.replace("\\", "/")


def scan_root(target_path: str | Path) -> Path:
    """Return the directory relative to which client-facing paths are shown."""
    target = Path(target_path)
    if target.is_file():
        return target.parent
    return target


def normalize_target_path(target_path: str | Path) -> str:
    """Hide workstation-specific parent directories in report metadata."""
    text = str(target_path)
    if PureWindowsPath(text).drive:
        return PureWindowsPath(text).name or "."
    return Path(text).name or "."


def normalize_diagnostic_paths(message: str, root: str | Path | None = None) -> str:
    """Remove workstation and temporary extraction roots from diagnostics."""
    normalized = message
    if root:
        root_text = str(root).rstrip("\\/")
        variants = {root_text, root_text.replace("\\", "/"), root_text.replace("/", "\\")}
        for variant in sorted(variants, key=len, reverse=True):
            normalized = re.sub(re.escape(variant), ".", normalized, flags=re.IGNORECASE)
    return re.sub(
        r"(?i)(?:[a-z]:[\\/]|/)[^\r\n]*?warden_extract_[^\\/\s:]+",
        "<archive-extraction>",
        normalized,
    )


def normalize_finding_path(
    path: str,
    root: str | Path | None = None,
    extracted_from: str | None = None,
) -> str:
    """Return a root-relative path or a logical archive chain."""
    windows = PureWindowsPath(path)
    posix = PurePosixPath(path.replace("\\", "/"))
    parts = windows.parts if windows.drive else posix.parts

    extract_index = next(
        (index for index, part in enumerate(parts) if part.casefold().startswith("warden_extract_")),
        None,
    )
    if extract_index is not None:
        chain: list[str] = []
        pending: list[str] = []
        for part in parts[extract_index + 1 :]:
            if part.endswith("__unpacked"):
                pending.append(part[: -len("__unpacked")])
                chain.append("/".join(pending))
                pending.clear()
            else:
                pending.append(part)
        if pending:
            chain.append("/".join(pending))
        member = " > ".join(chain)
        if extracted_from:
            origin = _relative_path(extracted_from, root)
            return " > ".join(part for part in (origin, member) if part)
        return member or windows.name or posix.name

    return _relative_path(path, root)
