"""
Installer/archive extraction - unpacks the bundled payload of installers
(NSIS, InnoSetup, MSI, self-extracting archives, plain ZIP/CAB/7z) so
their *contents* get scanned, not just the outer wrapper executable.

Real motivating example found during development: a signed, legitimate
installer's PE resources included a Microsoft Cabinet archive containing
five real DLLs (an updater, an activation helper, a UI framework, etc.) -
all completely unscanned by every other module, since none of them look
inside PE resource data for a nested archive format.

Uses the system `7z` binary (7-Zip / p7zip-full) since it has built-in
support for reading the PE resource layout of installer wrappers and a
wide range of archive formats through one consistent interface - this is
the same approach forensic/RE tooling generally uses for this problem
rather than hand-rolling a parser per installer framework. If `7z` isn't
on PATH, extraction is skipped entirely (never a hard failure) and the
outer file is still scanned exactly as before.

Safety:
- Bounded recursion depth (nested installers-within-installers).
- Bounded total extracted size (zip-bomb protection), checked against the
  archive listing before extraction and re-checked on disk afterwards.
- Path-escape guard: refuses any extracted member that would land outside
  the destination directory, even though 7z itself already guards against
  this - defense in depth costs nothing here.
- Bounded overall time via a subprocess timeout per extraction.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from core import NO_CONSOLE

# Extensions worth *attempting* extraction on. `.exe`/`.dll` are included
# because that's exactly the phantom-payload case above - an ordinary PE
# can still contain a nested Cabinet/NSIS/InnoSetup/7z payload in its
# resources even though the file itself is "just an executable".
ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".cab", ".msi", ".iso", ".rar", ".jar",
    ".exe", ".dll", ".asar",
}

DEFAULT_MAX_DEPTH = 2
# An unpacked Electron/Chromium app alone is ~400 MB, on top of the ~130 MB
# payload archive it came from; 500 MB silently skipped the actual app.
DEFAULT_MAX_TOTAL_BYTES = 2048 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 60


@dataclass
class ExtractResult:
    root: Path | None
    extracted_files: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False


def _sevenzip_path() -> str | None:
    """`7z` on PATH, else 7-Zip's default Windows install location (its
    installer does not add itself to PATH)."""
    found = shutil.which("7z")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base and (candidate := Path(base) / "7-Zip" / "7z.exe").is_file():
            return str(candidate)
    return None


def _innoextract_path() -> str | None:
    """`innoextract` on PATH (unpacks Inno Setup installers, which 7-Zip
    cannot - it only sees the outer PE's sections)."""
    return shutil.which("innoextract")


# Inno Setup stamps this into the installer's embedded data block. Present in
# both the setup .exe and its uninstaller; a reliable, cheap signature.
_INNO_MARKER = b"Inno Setup Setup Data"
_INNO_SCAN_BYTES = 16 * 1024 * 1024  # marker sits in the loader, within a few MB


def _is_inno_setup(path: Path) -> bool:
    """True if the PE is an Inno Setup installer/uninstaller."""
    try:
        with open(path, "rb") as f:
            return _INNO_MARKER in f.read(_INNO_SCAN_BYTES)
    except OSError:
        return False


def _extract_inno(innoextract: str, archive_path: Path, dest_dir: Path, timeout: int) -> bool:
    """Unpack an Inno Setup installer's files with innoextract. -e extracts,
    -d sets the output dir, --progress=0 keeps it quiet, -q silences chatter."""
    try:
        proc = subprocess.run(
            [innoextract, "-e", "-q", "--progress=0", "-d", str(dest_dir), str(archive_path)],
            capture_output=True, **NO_CONSOLE, text=True, errors="replace", timeout=timeout,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _list_archive(sevenzip: str, archive_path: Path, timeout: int) -> tuple[int, str] | None:
    """(total uncompressed size, archive type) per `7z l -slt`, or None if
    7z can't open it as an archive. The size is checked *before* extracting
    so a zip bomb is refused rather than written to disk first."""
    try:
        proc = subprocess.run(
            [sevenzip, "l", "-slt", str(archive_path)],
            capture_output=True, **NO_CONSOLE, text=True, errors="replace", timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    size = sum(int(n) for n in re.findall(r"^Size = (\d+)\s*$", proc.stdout, re.MULTILINE))
    kind = re.search(r"^Type = (\S+)", proc.stdout, re.MULTILINE)
    return size, kind.group(1) if kind else ""


def _safe_join(base: Path, *parts: str) -> Path:
    """Resolve a path under `base` and refuse anything that escapes it -
    defense in depth against a maliciously crafted archive, even though
    7z itself already guards against path traversal on extraction."""
    candidate = (base / Path(*parts)).resolve()
    base_resolved = base.resolve()
    if base_resolved not in candidate.parents and candidate != base_resolved:
        raise ValueError(f"Refusing to use path outside extraction root: {candidate}")
    return candidate


def _extract_asar(asar: Path, dest: Path) -> bool:
    """Unpack an Electron ASAR (7z cannot read it): a pickle header whose
    uint32 at 4 is the header size and at 12 the JSON index length, then the
    JSON index, then file bodies at base + offset. `unpacked` entries already
    sit next to the archive in app.asar.unpacked/ and are scanned from there."""
    try:
        with open(asar, "rb") as f:
            head = f.read(16)
            header_size, json_len = struct.unpack_from("<I", head, 4)[0], struct.unpack_from("<I", head, 12)[0]
            index = json.loads(f.read(json_len))
            base = 8 + header_size
            stack: list[tuple[dict, tuple[str, ...]]] = [(index, ())]
            while stack:
                node, rel = stack.pop()
                for name, entry in (node.get("files") or {}).items():
                    parts = rel + (name,)
                    if "files" in entry:
                        stack.append((entry, parts))
                        continue
                    if entry.get("unpacked") or "offset" not in entry:
                        continue
                    try:
                        out = _safe_join(dest, *parts)
                    except ValueError:
                        continue  # path-escape attempt in a crafted index
                    out.parent.mkdir(parents=True, exist_ok=True)
                    f.seek(base + int(entry["offset"]))
                    out.write_bytes(f.read(int(entry["size"])))
        return True
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        return False


def _extract_one(sevenzip: str, archive_path: Path, dest_dir: Path, timeout: int) -> tuple[bool, str]:
    """Run `7z x` once. Returns (success, message)."""
    try:
        proc = subprocess.run(
            [sevenzip, "x", "-y", f"-o{dest_dir}", str(archive_path)],
            capture_output=True, **NO_CONSOLE, text=True, errors="replace", timeout=timeout,
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "unknown 7z error").strip()[:300]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, f"extraction timed out after {timeout}s"
    except OSError as e:
        return False, str(e)


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def extract_archive_recursive(
    archive_path: str | Path,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ExtractResult:
    """
    Extract `archive_path` into a fresh temp directory, then recursively
    extract any nested archive-looking files found inside, up to
    `max_depth` levels. Returns every extracted file path (across all
    levels) for the caller to feed into the normal scan pipeline.

    The caller owns cleanup of `result.root` (a tempfile.mkdtemp()
    directory) once scanning is done.
    """
    archive_path = Path(archive_path)
    result = ExtractResult(root=None)

    sevenzip = _sevenzip_path()
    if sevenzip is None:
        result.warnings.append("7z not found (PATH or Program Files\\7-Zip) - archive/installer extraction skipped")
        return result

    root = Path(tempfile.mkdtemp(prefix="warden_extract_"))
    result.root = root

    # (path_to_extract, destination_subdir, depth)
    queue: list[tuple[Path, Path, int]] = [(archive_path, root, 0)]
    seen_total_bytes = 0
    # 7z opens any plain PE as "Type = PE" and dumps its raw sections. Those
    # bytes were already covered by the PE string scan, so only nested
    # archives found inside them are kept (see the post-pass below).
    pe_dests: list[Path] = []

    while queue:
        current, dest, depth = queue.pop(0)
        if depth > max_depth:
            result.warnings.append(f"Max nesting depth ({max_depth}) reached, stopped at {current.name}")
            continue

        is_asar = current.suffix.lower() == ".asar"
        # Inno Setup installers: 7-Zip only sees the outer PE's sections, never
        # the bundled application. innoextract unpacks them; without it we flag
        # the coverage gap instead of silently scanning only the wrapper.
        is_inno = not is_asar and current.suffix.lower() == ".exe" and _is_inno_setup(current)
        innoextract = _innoextract_path() if is_inno else None
        if is_inno and innoextract is None:
            result.warnings.append(
                f"{current.name} is an Inno Setup installer; its bundled application was NOT unpacked "
                "(7-Zip cannot read Inno payloads). Install 'innoextract' and re-scan for full coverage."
            )
            continue

        if is_asar:
            listed, kind = current.stat().st_size, "ASAR"
        elif is_inno:
            listed, kind = current.stat().st_size, "INNO"
        else:
            listing = _list_archive(sevenzip, current, timeout_seconds)
            if listing is None:
                # Not every .exe/.dll IS an archive - 7z failing on a plain
                # PE with no embedded archive payload is the expected common
                # case, not an error worth surfacing.
                continue
            listed, kind = listing
        if seen_total_bytes + listed > max_total_bytes:
            result.truncated = True
            result.warnings.append(
                f"Skipped {current.name}: extracting it would exceed the "
                f"{max_total_bytes // (1024*1024)} MB cap ({listed // (1024*1024)} MB listed)"
            )
            continue

        dest.mkdir(parents=True, exist_ok=True)
        if is_asar:
            ok = _extract_asar(current, dest)
        elif is_inno:
            ok = _extract_inno(innoextract, current, dest, timeout_seconds)
            if not ok:
                result.warnings.append(f"innoextract failed on {current.name}; its payload was not scanned")
        else:
            ok = _extract_one(sevenzip, current, dest, timeout_seconds)[0]
        if not ok:
            continue
        if kind == "PE":
            pe_dests.append(dest)

        # Re-measure what actually landed on disk (the listing can understate).
        seen_total_bytes = _dir_size(root)
        if seen_total_bytes > max_total_bytes:
            result.truncated = True
            result.warnings.append(
                f"Extracted content exceeded {max_total_bytes // (1024*1024)} MB cap - "
                f"stopped extracting further nested archives"
            )
            break

        for extracted in dest.rglob("*"):
            if not extracted.is_file():
                continue
            try:
                _safe_join(root, str(extracted.relative_to(root)))
            except ValueError:
                result.warnings.append(f"Skipped path-escape attempt: {extracted}")
                continue
            result.extracted_files.append(extracted)
            # Deliberately NOT gated on file extension: files extracted
            # from a PE's resource section commonly have no extension at
            # all (e.g. "2000", "3000" - the raw RCDATA resource ID) even
            # though the content itself is a real nested archive (this is
            # exactly the Cabinet-archive-in-a-resource case that
            # motivated this feature). 7z fails fast and harmlessly on
            # anything that isn't actually an archive, so attempting
            # extraction unconditionally (bounded by depth/size caps) is
            # cheap and far more reliable than guessing from a filename.
            try:
                too_small = extracted.stat().st_size < 64
            except OSError:
                too_small = True
            if depth < max_depth and not too_small and extracted != current:
                queue.append((extracted, extracted.parent / f"{extracted.name}__unpacked", depth + 1))

    # Drop raw PE section dumps, keeping only what was unpacked from them.
    for dest in pe_dests:
        for f in [p for p in dest.rglob("*") if p.is_file()]:
            if not any(part.endswith("__unpacked") for part in f.relative_to(dest).parts):
                f.unlink(missing_ok=True)
    result.extracted_files = [f for f in result.extracted_files if f.exists()]
    return result


def cleanup(result: ExtractResult) -> None:
    if result.root and result.root.exists():
        shutil.rmtree(result.root, ignore_errors=True)
