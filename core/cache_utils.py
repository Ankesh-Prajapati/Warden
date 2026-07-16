"""Small SHA-256 backed scan cache for incremental module runs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = ".warden_cache"
DEFAULT_CACHE_FILE = "sha256_scan_cache.json"


class ScanCache:
    def __init__(self, root: str | Path, enabled: bool = True, cache_file: str | Path | None = None):
        self.root = Path(root)
        self.enabled = enabled
        self.path = Path(cache_file) if cache_file else self.root / DEFAULT_CACHE_DIR / DEFAULT_CACHE_FILE
        self.data: dict[str, dict[str, Any]] = {}
        if enabled:
            self._load()

    def _load(self) -> None:
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.data = {}

    def save(self) -> None:
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass

    def key_for(self, path: str | Path) -> str:
        p = Path(path)
        try:
            return str(p.resolve().relative_to(self.root.resolve()))
        except Exception:
            return str(p.resolve())

    def signature_for(self, path: str | Path) -> dict[str, Any]:
        stat = Path(path).stat()
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}

    def unchanged(self, path: str | Path, module: str) -> bool:
        if not self.enabled:
            return False
        try:
            return self.data.get(self.key_for(path), {}).get(module, {}).get("sig") == self.signature_for(path)
        except OSError:
            return False

    def mark_scanned(self, path: str | Path, module: str, sha256: str) -> None:
        if not self.enabled:
            return
        try:
            self.data.setdefault(self.key_for(path), {})[module] = {
                "sig": self.signature_for(path),
                "sha256": sha256,
            }
        except OSError:
            return


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
