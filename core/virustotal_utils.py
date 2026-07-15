"""
VirusTotal integration for binary reputation checks.

Design principle: **hash lookup only, by default.** During a VAPT
engagement the binaries being scanned are frequently a client's
proprietary, unreleased software under NDA — silently uploading them to
a third-party public service would be a serious confidentiality/contract
breach, independent of whether it's also a security concern. So the
default and recommended mode only ever sends a SHA-256 hash to
VirusTotal's `/files/{hash}` lookup endpoint, which tells you whether
*that exact binary* has been seen and flagged before, without the binary
itself ever leaving the analyst's machine.

Uploading unknown files for fresh analysis is supported but is a
separate, explicitly opt-in action (`upload_unknown=True`) that the
caller must deliberately choose per scan — see reputation_module.py.

Works against the VirusTotal public (free) API tier: 4 requests/minute,
500/day, 15.5K/month. Paid tiers lift those limits but nothing about the
request shape changes — same client works for API key of either tier.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from core.logging_config import get_logger

logger = get_logger("virustotal")

API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 20

# Public/free-tier default: 4 req/min == 1 every 15s. Paid keys can raise
# this via VTClient(min_interval_seconds=...); we default conservatively
# so a free-tier key never gets rate-limited/banned by surprise.
DEFAULT_MIN_INTERVAL_SECONDS = 15.0


@dataclass
class VTVerdict:
    sha256: str
    found: bool = False                  # False = not in VT's database at all
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    vendor_flags: list[str] = field(default_factory=list)  # engine names that flagged it
    permalink: str = ""
    error: str | None = None             # set on network/API failure; verdict is inconclusive

    @property
    def is_flagged(self) -> bool:
        return self.found and (self.malicious > 0 or self.suspicious > 0)

    @property
    def detection_ratio(self) -> str:
        flagged = self.malicious + self.suspicious
        return f"{flagged}/{self.total_engines}" if self.total_engines else "0/0"


def compute_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


class VTRateLimitError(Exception):
    pass


class VTAuthError(Exception):
    pass


class VTClient:
    def __init__(self, api_key: str, min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS):
        if not api_key or not api_key.strip():
            raise ValueError("VirusTotal API key is required.")
        self.api_key = api_key.strip()
        self.min_interval_seconds = max(0.0, min_interval_seconds)
        self._last_request_at = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        wait = self.min_interval_seconds - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _request(self, path: str) -> dict:
        self._throttle()
        req = urllib.request.Request(
            f"{API_BASE}{path}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}  # not found in VT's database — not an error condition
            if e.code == 401 or e.code == 403:
                raise VTAuthError(f"VirusTotal rejected the API key (HTTP {e.code}).") from e
            if e.code == 429:
                raise VTRateLimitError("VirusTotal rate limit exceeded — slow down or upgrade your API tier.") from e
            raise
        except urllib.error.URLError as e:
            raise ConnectionError(f"Could not reach VirusTotal: {e.reason}") from e

    def lookup_hash(self, sha256: str) -> VTVerdict:
        """
        Look up a file by its SHA-256 hash only. Never uploads file content —
        this is the safe, confidentiality-preserving default described above.
        """
        verdict = VTVerdict(sha256=sha256)
        try:
            data = self._request(f"/files/{sha256}")
        except (VTAuthError, VTRateLimitError, ConnectionError) as e:
            verdict.error = str(e)
            logger.warning("VirusTotal lookup failed for %s: %s", sha256, e)
            return verdict
        except Exception as e:  # never let a VT hiccup break the scan
            verdict.error = f"Unexpected VirusTotal error: {e}"
            logger.error("Unexpected VirusTotal error for %s: %s", sha256, e)
            return verdict

        if not data:
            return verdict  # found=False: genuinely unknown to VT, not an error

        try:
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})
            verdict.found = True
            verdict.malicious = stats.get("malicious", 0)
            verdict.suspicious = stats.get("suspicious", 0)
            verdict.undetected = stats.get("undetected", 0)
            verdict.harmless = stats.get("harmless", 0)
            verdict.total_engines = sum(stats.values()) if stats else 0
            verdict.vendor_flags = sorted(
                vendor for vendor, r in results.items()
                if r.get("category") in ("malicious", "suspicious")
            )
            verdict.permalink = f"https://www.virustotal.com/gui/file/{sha256}"
        except (KeyError, TypeError) as e:
            verdict.error = f"Unexpected VirusTotal response shape: {e}"
            logger.error("Unexpected VirusTotal response shape for %s: %s", sha256, e)

        return verdict

    def upload_file(self, path: Path) -> VTVerdict:
        """
        Explicitly opt-in: upload file content for fresh analysis when it
        isn't already known to VT. NOT called by default anywhere in
        Warden — see the module docstring for why. Only wire this in behind
        a UI control that makes the confidentiality tradeoff obvious.
        """
        import mimetypes
        import uuid

        sha256 = compute_sha256(path)
        boundary = uuid.uuid4().hex
        with open(path, "rb") as f:
            file_bytes = f.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
            f"Content-Type: {mimetypes.guess_type(path.name)[0] or 'application/octet-stream'}\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        self._throttle()
        req = urllib.request.Request(
            f"{API_BASE}/files",
            data=body,
            headers={
                "x-apikey": self.api_key,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=max(REQUEST_TIMEOUT, 60)) as resp:
                json.loads(resp.read().decode("utf-8"))  # analysis submitted; poll not implemented in v1
        except Exception as e:
            v = VTVerdict(sha256=sha256)
            v.error = f"Upload failed: {e}"
            return v

        # VT queues uploaded files for analysis rather than scoring instantly;
        # a follow-up lookup_hash() call (often minutes later) is needed to
        # get a verdict. Callers that need this should poll separately.
        return self.lookup_hash(sha256)


# SHA-256 of the EICAR antivirus test string — a standard, harmless test
# file that every AV engine recognizes and every VT account has permission
# to look up. Used purely to verify a key/connection work, not as a real
# malware indicator. Computed directly from the EICAR test string bytes
# (hashlib.sha256(EICAR_BYTES).hexdigest()) rather than hand-transcribed,
# after an earlier transcription was accidentally short by one character.
EICAR_TEST_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def test_api_key(api_key: str) -> tuple[bool, str]:
    """
    Quick standalone check: does this API key actually work? Returns
    (ok, message). Distinguishes an invalid/unverified key from a network
    problem, so the caller can show something more useful than a bare
    'it failed' — this is exactly the ambiguity that made an earlier key
    look broken when the real cause was a blocked network path.
    """
    try:
        client = VTClient(api_key, min_interval_seconds=0)
    except ValueError as e:
        return False, str(e)

    verdict = client.lookup_hash(EICAR_TEST_SHA256)
    if verdict.error:
        return False, verdict.error
    if verdict.found:
        return True, f"Key works — VirusTotal reachable, {verdict.total_engines} engines reporting."
    # Not finding the EICAR hash would be extremely unusual (it's one of
    # the most-submitted files in VT's history) but isn't itself a key
    # failure — the connection and auth both clearly worked to get here.
    return True, "Key works — VirusTotal reachable, though the test lookup returned no data."
