"""
Shannon entropy scoring for high-entropy string detection.

Used to catch secrets that don't match a known regex pattern (custom API key
formats, random tokens, etc.) by flagging substrings with unusually high
randomness — the same technique used by gitleaks/trufflehog's entropy checks.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# Candidate substrings are extracted with this charset (typical secret alphabets:
# base64, hex, and common key-ish separators).
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_\-=]{20,}")

# Standard GUID/UUID shapes (with or without braces/dashes) are hex data,
# not secrets — compiled binaries and config files are full of them
# (class IDs, component IDs, .NET type GUIDs) and their entropy sits right
# at the hex-charset threshold, making them a common false-positive source.
_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}\}?$"
)

# Tuned thresholds. Base64-like strings have max entropy ~6 bits/char (log2(64)).
# Hex strings have max entropy 4 bits/char (log2(16)). We use two thresholds
# depending on the apparent charset to reduce false positives on hex-only data.
HEX_CHARSET = set("0123456789abcdefABCDEF")
DEFAULT_B64_THRESHOLD = 4.3
DEFAULT_HEX_THRESHOLD = 3.3
MIN_LENGTH = 20
MAX_LENGTH = 4096  # guard against pathological giant single-token lines


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_high_entropy(
    s: str,
    b64_threshold: float = DEFAULT_B64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> bool:
    """Decide if a candidate string looks like a random secret vs normal text."""
    if not (MIN_LENGTH <= len(s) <= MAX_LENGTH):
        return False

    ent = shannon_entropy(s)
    looks_hex = all(c in HEX_CHARSET for c in s)

    if looks_hex:
        return ent >= hex_threshold
    return ent >= b64_threshold


def find_high_entropy_candidates(
    text: str,
    b64_threshold: float = DEFAULT_B64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> list[tuple[str, int]]:
    """
    Scan text for high-entropy substrings.

    Returns list of (matched_string, start_offset) tuples. Deduplicates
    identical matches to avoid report noise on repeated tokens.
    """
    seen: set[str] = set()
    results: list[tuple[str, int]] = []

    for m in _CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        if candidate in seen:
            continue
        # Skip obvious non-secrets: repeated-char runs, all-digit sequences
        # (often just numeric IDs), and standard GUID/UUID shapes.
        if len(set(candidate)) <= 2:
            continue
        if candidate.isdigit():
            continue
        if _GUID_RE.match(candidate):
            continue
        if is_high_entropy(candidate, b64_threshold, hex_threshold):
            seen.add(candidate)
            results.append((candidate, m.start()))

    return results
