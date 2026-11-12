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


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def extraction_repro(
    path: str,
    extracted_from: str | None,
    root: str | Path | None = None,
) -> tuple[str, list[str]] | None:
    """For a file Warden unpacked from a package: (local path, PowerShell
    commands that recreate it with 7-Zip / asar), mirroring Warden's own
    `<name>__unpacked` layout. None for files that exist on disk as-is."""
    windows = PureWindowsPath(path)
    parts = windows.parts if windows.drive else PurePosixPath(path.replace("\\", "/")).parts
    idx = next((i for i, p in enumerate(parts) if p.casefold().startswith("warden_extract_")), None)
    if idx is None or not extracted_from:
        return None
    cur = "warden_extracted"
    steps = [f"7z x {_ps(_relative_path(extracted_from, root))} -o{_ps(cur)}"]
    for part in parts[idx + 1 :]:
        nxt = f"{cur}\\{part}"
        if part.endswith("__unpacked"):
            src = f"{cur}\\{part[: -len('__unpacked')]}"
            steps.append(
                f"npx --yes @electron/asar extract {_ps(src)} {_ps(nxt)}"
                if src.lower().endswith(".asar")
                else f"7z x {_ps(src)} -o{_ps(nxt)}"
            )
        cur = nxt
    return cur, steps


def localize_poc(poc: str, original_path: str, display_path: str, extracted_from: str | None, root) -> str:
    """Make PoC commands runnable: paths inside a package get a recreate-it
    preamble and a `$f` variable instead of the logical "a.exe > b.dll" chain."""
    repro = extraction_repro(original_path, extracted_from, root)
    if not poc or repro is None:
        return poc.replace(original_path, display_path)
    local, steps = repro
    body = (
        poc.replace(f"Location: {original_path}", f"Location: {display_path}")
        .replace(f"r'{original_path}'", "r'$f'")
        .replace(_ps(original_path), "$f")
        .replace(original_path, "$f")
    )
    preamble = (
        "0. This file is bundled inside the scanned package. Recreate it first (PowerShell, 7-Zip):\n"
        + "".join(f"     {s}\n" for s in steps)
        + f"     $f = {_ps(local)}\n"
        + "   The commands below use $f for that file.\n\n"
    )
    return preamble + body


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
