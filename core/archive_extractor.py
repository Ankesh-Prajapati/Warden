"""
Installer/archive extraction — unpacks the bundled payload of installers
(NSIS, InnoSetup, MSI, self-extracting archives, plain ZIP/CAB/7z) so
their *contents* get scanned, not just the outer wrapper executable.

Real motivating example found during development: a signed, legitimate
installer's PE resources included a Microsoft Cabinet archive containing
five real DLLs (an updater, an activation helper, a UI framework, etc.) —
all completely unscanned by every other module, since none of them look
inside PE resource data for a nested archive format.

Uses the system `7z` binary (7-Zip / p7zip-full) since it has built-in
support for reading the PE resource layout of installer wrappers and a
wide range of archive formats through one consistent interface — this is
the same approach forensic/RE tooling generally uses for this problem
rather than hand-rolling a parser per installer framework. If `7z` isn't
on PATH, extraction is skipped entirely (never a hard failure) and the
outer file is still scanned exactly as before.

Safety:
- Bounded recursion depth (nested installers-within-installers).
- Bounded total extracted size (zip-bomb protection).
- Path-escape guard: refuses any extracted member that would land outside
  the destination directory, even though 7z itself already guards against
  this — defense in depth costs nothing here.
- Bounded overall time via a subprocess timeout per extraction.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Extensions worth *attempting* extraction on. `.exe`/`.dll` are included
# because that's exactly the phantom-payload case above — an ordinary PE
# can still contain a nested Cabinet/NSIS/InnoSetup/7z payload in its
# resources even though the file itself is "just an executable".
ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".cab", ".msi", ".iso", ".rar", ".jar",
    ".exe", ".dll",
}

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024  # 500 MB extracted-content cap
DEFAULT_TIMEOUT_SECONDS = 60


@dataclass
class ExtractResult:
    root: Path | None
    extracted_files: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False


def _sevenzip_available() -> bool:
    return shutil.which("7z") is not None


def _looks_extractable(path: Path) -> bool:
    return path.suffix.lower() in ARCHIVE_EXTENSIONS


def _safe_join(base: Path, *parts: str) -> Path:
    """Resolve a path under `base` and refuse anything that escapes it —
    defense in depth against a maliciously crafted archive, even though
    7z itself already guards against path traversal on extraction."""
    candidate = (base / Path(*parts)).resolve()
    base_resolved = base.resolve()
    if base_resolved not in candidate.parents and candidate != base_resolved:
        raise ValueError(f"Refusing to use path outside extraction root: {candidate}")
    return candidate


def _extract_one(archive_path: Path, dest_dir: Path, timeout: int) -> tuple[bool, str]:
    """Run `7z x` once. Returns (success, message)."""
    try:
        proc = subprocess.run(
            ["7z", "x", "-y", f"-o{dest_dir}", str(archive_path)],
            capture_output=True, text=True, timeout=timeout,
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

    if not _sevenzip_available():
        result.warnings.append("7z not found on PATH — archive/installer extraction skipped")
        return result

    root = Path(tempfile.mkdtemp(prefix="warden_extract_"))
    result.root = root

    # (path_to_extract, destination_subdir, depth)
    queue: list[tuple[Path, Path, int]] = [(archive_path, root, 0)]
    seen_total_bytes = 0

    while queue:
        current, dest, depth = queue.pop(0)
        if depth > max_depth:
            result.warnings.append(f"Max nesting depth ({max_depth}) reached, stopped at {current.name}")
            continue

        dest.mkdir(parents=True, exist_ok=True)
        ok, err = _extract_one(current, dest, timeout_seconds)
        if not ok:
            # Not every .exe/.dll IS an archive — 7z failing on a plain
            # PE with no embedded archive payload is the expected common
            # case, not an error worth surfacing.
            continue

        seen_total_bytes = _dir_size(root)
        if seen_total_bytes > max_total_bytes:
            result.truncated = True
            result.warnings.append(
                f"Extracted content exceeded {max_total_bytes // (1024*1024)} MB cap — "
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
            # all (e.g. "2000", "3000" — the raw RCDATA resource ID) even
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

    return result


def cleanup(result: ExtractResult) -> None:
    if result.root and result.root.exists():
        shutil.rmtree(result.root, ignore_errors=True)
