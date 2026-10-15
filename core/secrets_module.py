"""
Module 1 — Secrets & Config Exposure Scanner.

Scans a target directory tree for:
  - Hardcoded secrets/credentials in text/config files (regex + entropy)
  - Hardcoded secrets embedded as strings inside PE binaries (.exe/.dll)
  - Plaintext credential storage indicators in config/registry-export files
  - Overly permissive file permissions on files containing sensitive data

Emits a flat list of core.models.Finding objects, which the orchestrator
(scanner.py) merges with output from the other modules.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from core.cache_utils import ScanCache, sha256_file
from core.config_intel import extract_interesting_settings
from core.entropy import find_high_entropy_candidates
from core.fs_walk import (
    check_permissive_permissions,
    classify_file,
    iter_target_files,
    read_text_safely,
)
from core.models import Finding, Severity
from core.pe_utils import extract_strings_from_bytes, get_version_strings, is_pe_file, parse_pe
from core.indicator_utils import is_version_attribute_context
from core.rules import Rule, load_rules

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
DB_URI_RE = re.compile(
    r"\b(?P<scheme>postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|sqlserver|jdbc:[a-z0-9]+)://[^\s'\"<>]+",
    re.IGNORECASE,
)
# Enhanced cloud credential patterns
AWS_SESSION_TOKEN_RE = re.compile(r'\b(A3T[A-Z0-9]|ATOA|AGOA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{10,}\b')
AZURE_APP_TOKEN_RE = re.compile(r'(?i)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+.*?(?:azure|microsoft)')
GCP_OAUTH_TOKEN_RE = re.compile(r'\bya29\.[A-Za-z0-9_-]+\b')
CORRELATION_KEYS = {
    "username": ("user", "username", "uid", "login"),
    "password": ("pass", "password", "pwd"),
    "endpoint": ("host", "endpoint", "url", "server", "base_url"),
    "api_key": ("api_key", "apikey", "token", "secret", "client_secret", "key"),
}

# Placeholder/test values that regex rules commonly false-positive on.
# Evidence matching these (case-insensitive) is downgraded to Low confidence
# rather than dropped entirely, so analysts can still eyeball and dismiss.
# Placeholder/test *values* — these mark an obviously fake credential value,
# e.g. `api_key = changeme`. Deliberately does NOT include generic words like
# "secret" or "password", since those are normal parts of legitimate
# variable names (client_secret, db_password, secret_key, ...) — matching
# them against the whole evidence string (as opposed to just the value)
# used to downgrade most real credential findings to Low confidence, which
# is the opposite of what a VAPT tool should do.
PLACEHOLDER_MARKERS = {
    "changeme", "changeit", "example", "your_api_key", "xxxxxxxx",
    "test123", "dummy", "placeholder",
    "insert_key_here", "todo", "yourpassword", "replaceme", "sample",
    "<insert", "<your", "<api", "notarealkey", "notreal", "fakekey",
    "demo", "synthetic", "test_only", "not_valid",
}


def _isolate_value(evidence: str) -> str:
    """
    Best-effort isolation of the *value* side of a `key = value` /
    `key: value` match, so placeholder detection judges the credential
    itself rather than the variable name it's assigned to (which routinely
    contains words like "secret" or "password" even for real credentials).
    For connection strings, attempts to isolate values by looking for
    key=value patterns within semicolon/comma-separated fields,
    prioritizing security-relevant fields like passwords.
    Falls back to the original key-value isolation if no connection string
    pattern is found.
    """
    # First, try to handle as a connection string with semicolon/comma delimited key=value pairs
    if ';' in evidence or ',' in evidence:
        # Split by both semicolon and comma to get potential key=value pairs
        import re
        pairs = re.split(r'[;,]\s*', evidence)

        # First pass: look for password-related fields (most likely to contain secrets)
        password_keywords = {"pass", "password", "pwd", "secret", "key", "token"}
        for pair in pairs:
            if '=' in pair:
                # Split on first '=' to get key and value
                key_value = pair.split('=', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip().lower()
                    value = key_value[1].strip().strip("'\"")
                    # Check if this looks like a password/security field
                    if any(pwd_keyword in key for pwd_keyword in password_keywords):
                        if value:
                            return value

        # Second pass: return the first non-empty value if no password field found
        for pair in pairs:
            if '=' in pair:
                key_value = pair.split('=', 1)
                if len(key_value) == 2:
                    value = key_value[1].strip().strip("'\"")
                    if value:
                        return value

    # Fallback to original behavior for key-value pairs
    for sep in ("=", ":"):
        if sep in evidence:
            candidate = evidence.rsplit(sep, 1)[-1].strip().strip("'\"")
            if candidate:
                return candidate
    return evidence


def _looks_like_placeholder(evidence: str) -> bool:
    lowered = _isolate_value(evidence).lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


# Sequences that essentially only ever appear in a regex pattern literal,
# never in a real credential value. Guards against a specific, easy-to-hit
# false positive: a credential-detection rule matching its own pattern
# definition when scanning a rule-pack file (this tool's own rules/*.yaml,
# or any target that happens to ship its own regex-based validators/WAF
# rules/security tooling — not a Warden-specific edge case).
#
# Requires >=2 distinct markers before suppressing a match, so a real
# secret that coincidentally contains one stray bracket or backslash isn't
# silently dropped — an actual regex pattern is a dense cluster of these,
# not one incidental character.
_REGEX_SYNTAX_MARKERS = (
    "(?i)", "(?:", "(?=", "(?!", r"\s*", r"\s+", r"\b", r"\d+", r"\w+",
    "[^", "]?", "{0,", "{1,", "{2,", "{3,", "{4,", "{6,",
)


def _looks_like_regex_definition(evidence: str) -> bool:
    hits = sum(1 for marker in _REGEX_SYNTAX_MARKERS if marker in evidence)
    return hits >= 2


def _looks_like_sequential_charset(evidence: str) -> bool:
    """
    Catches charset/alphabet tables ("0123456789abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ") — a near-universal constant embedded in
    binaries for base64/base32/hex encoding tables, sorting routines, etc.
    These score as high-entropy by character *diversity* even though
    they're maximally predictable (fully sequential), which is exactly
    the opposite of what makes a real secret high-entropy — a genuine
    secret's high entropy comes from unpredictability, not from happening
    to use every letter once in alphabetical order.

    Checks whether the candidate, once we look at only its
    letters/digits, is itself an unbroken run of consecutive characters
    (allowing either direction, and allowing the value to be a
    contiguous slice of the alphabet/digit sequence rather than
    requiring the full 26/10 characters).
    """
    core = "".join(c for c in evidence if c.isalnum())
    if len(core) < 8:
        return False

    def _is_sequential_run(s: str) -> bool:
        if len(s) < 2:
            return True
        chars = s.lower()
        forward = all(ord(chars[i + 1]) - ord(chars[i]) == 1 for i in range(len(chars) - 1))
        backward = all(ord(chars[i]) - ord(chars[i + 1]) == 1 for i in range(len(chars) - 1))
        return forward or backward

    # Split into maximal same-type runs (digits vs letters) so a
    # concatenated charset table like "0123456789abcdefg..." — digits
    # then letters, the exact real-world case this heuristic exists for —
    # is checked as two sequential runs rather than one mixed string that
    # trivially fails a single ascending-by-one check across the digit/
    # letter boundary.
    runs = re.findall(r"\d+|[A-Za-z]+", core)
    if not runs:
        return False
    substantial_runs = [r for r in runs if len(r) >= 6]
    if not substantial_runs:
        return False
    return all(_is_sequential_run(r) for r in runs)


def _looks_like_partitioned_charset(evidence: str) -> bool:
    """
    Catches charset tables built from a small number of contiguous
    alphabet slices concatenated together (e.g. "CDEFGHIJSTUVWXYZ" is
    C-J plus S-Z) — a common pattern for filename-safe/ambiguity-
    avoiding encoding alphabets. Like a fully sequential run, this is a
    fixed, highly predictable constant, not a real secret, even though
    Shannon entropy alone can't tell the difference (every character
    still appears at most once).

    Deliberately conservative: requires very few breaks (<=2, i.e. at
    most 3 contiguous alphabet slices) AND each slice to be a
    substantial run (>=4 letters) — a genuine random secret's unique
    letters are scattered with many small gaps, not organized into a
    couple of long contiguous chunks. An earlier, looser version of
    this check incorrectly matched real secrets (e.g. AWS/Stripe key
    patterns), so err on the side of under-matching here.
    """
    for case_letters in (
        "".join(c for c in evidence if c.isupper()),
        "".join(c for c in evidence if c.islower()),
    ):
        if len(case_letters) < 12:
            continue
        unique_sorted = sorted(set(case_letters))
        if len(unique_sorted) < 12:
            continue
        runs = [[unique_sorted[0]]]
        for prev, cur in zip(unique_sorted, unique_sorted[1:]):
            if ord(cur) - ord(prev) == 1:
                runs[-1].append(cur)
            else:
                runs.append([cur])
        if len(runs) <= 3 and all(len(r) >= 4 for r in runs):
            return True
    return False


_IDENTIFIER_PREFIX_MARKERS = (
    "fn_", "sb_", "proc_", "sp_", "usp_", "fun_", "func_", "cmd_", "btn_", "frm_", "cls_",
)


def _looks_like_code_identifier(evidence: str) -> bool:
    """
    Catches VB6/SQL-style function, stored-procedure, and form/control
    identifiers (e.g. "Fn_Activate_AutoMailer_ProgramId_As_MailSubject",
    "SB_UPDATE_FCRCPTBL_FiscalReceiptNumber") — underscore-delimited,
    word-like tokens that score as high-entropy from case/underscore
    mixing, but are source-code identifiers pulled from a binary's
    string table, not secrets.
    """
    low = evidence.lower()
    if not any(low.startswith(p) for p in _IDENTIFIER_PREFIX_MARKERS):
        return False
    segments = [s for s in evidence.split("_") if s]
    return len(segments) >= 3 and all(s.isalpha() or s.isdigit() for s in segments)


_IMAGE_MAGIC_BYTES = (
    b"\xff\xd8\xff",       # JPEG
    b"\x89PNG\r\n\x1a\n",  # PNG
    b"GIF87a", b"GIF89a",  # GIF
    b"BM",                 # BMP
)


def _looks_like_embedded_image_blob(evidence: str) -> bool:
    """
    Catches base64-encoded image data (icons/toolbar bitmaps embedded as
    resource strings in legacy VB6/MFC forms) — decodes cleanly as valid
    base64 and the decoded bytes start with a known image file magic
    number. High Shannon entropy is expected for compressed image data;
    it isn't a secret.
    """
    candidate = evidence.strip()
    if len(candidate) < 40 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate):
        return False
    try:
        decoded = base64.b64decode(candidate[:64] + "==", validate=False)
    except (binascii.Error, ValueError):
        return False
    return decoded.startswith(_IMAGE_MAGIC_BYTES)


_CERT_AUTHORITY_MARKERS = (
    "digicert", "verisign", "sectigo", "globalsign", "comodo", "thawte",
    "geotrust", "entrust", "godaddy", "letsencrypt", "let's encrypt",
    "trustedroot", "trusted root", "codesigning", "code signing",
    "timestamping", "time stamping", "certificate authority",
)


def _looks_like_certificate_authority_string(evidence: str) -> bool:
    """
    Catches certificate-chain/CA name fragments (e.g. embedded
    "DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1" strings from a
    binary's own Authenticode certificate chain) — these are long,
    mixed-case, numeric-heavy strings that score as high-entropy the same
    way a real secret would, but they're public certificate authority
    names, not credentials. Any signed binary embeds several of these as
    plain strings; they're pure noise for a secrets scan.
    """
    lowered = evidence.lower()
    return any(marker in lowered for marker in _CERT_AUTHORITY_MARKERS)


_HEX_DIGEST_LENGTHS = {32, 40, 56, 64, 96, 128}
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_WAMP_CALL_ID_RE = re.compile(r"\bwamp\b.{0,100}\bcall[\s_-]*id\b", re.IGNORECASE)
_COMPILER_SYMBOL_RE = re.compile(
    r"(?:\.\?AV|(?:^|\s)\?[\w?$@]+@|__imp_|_Z(?:N|TS|TV))",
    re.IGNORECASE,
)
_RESOURCE_MANIFEST_RE = re.compile(
    r"(?i)(?:\bthemes?/|manifest\.(?:json|ya?ml)\b|"
    r"\.(?:png|svg|qss|theme)\b)"
)
_IP_NETWORK_CONTEXT_RE = re.compile(
    r"(?i)(?:https?://|\b(?:dns|ip|ipv4|host|server|endpoint|proxy|socket|"
    r"network|address|remote|listen|connect|url)\b)"
)


def _looks_like_hash_or_thumbprint(candidate: str) -> bool:
    return len(candidate) in _HEX_DIGEST_LENGTHS and bool(_HEX_DIGEST_RE.fullmatch(candidate))


def _looks_like_crypto_algorithm_identifier(candidate: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", candidate.lower())
    if re.fullmatch(r"(?:id)?gost(?:r)?\d{4,7}[a-z0-9]*", normalized):
        return True
    if normalized.startswith("pbe") and any(
        algorithm in normalized
        for algorithm in ("sha1", "sha256", "sha384", "sha512", "aes", "des", "rc4")
    ):
        return True
    if re.fullmatch(
        r"dhsinglepass(?:std|cofactor)dhsha\d+kdfscheme",
        normalized,
    ):
        return True
    return bool(
        re.fullmatch(
            r"(?:id)?(?:sha(?:1|224|256|384|512)(?:with)?(?:rsa|ecdsa)?"
            r"|md[245](?:with)?rsa|aes(?:128|192|256)(?:cbc|cfb|gcm)?"
            r"|rsa(?:encryption|oaep|pkcs1)|ed25519|x25519)",
            normalized,
        )
    )


def _entropy_candidate_has_benign_context(
    candidate: str,
    content: str,
    offset: int,
) -> bool:
    if (
        _looks_like_sequential_charset(candidate)
        or _looks_like_partitioned_charset(candidate)
        or _looks_like_code_identifier(candidate)
        or _looks_like_embedded_image_blob(candidate)
        or _looks_like_certificate_authority_string(candidate)
        or _looks_like_hash_or_thumbprint(candidate)
        or _looks_like_crypto_algorithm_identifier(candidate)
        or _looks_like_deterministic_hex_table(candidate)
    ):
        return True

    start = content.rfind("\n", 0, offset) + 1
    end = content.find("\n", offset + len(candidate))
    if end < 0:
        end = len(content)
    context = content[start:end]
    if _WAMP_CALL_ID_RE.search(context) or _COMPILER_SYMBOL_RE.search(context):
        return True

    candidate_lower = candidate.lower()
    if (
        _RESOURCE_MANIFEST_RE.search(context)
        and (
            candidate_lower.startswith("png")
            or "manifest" in candidate_lower
            or "theme" in candidate_lower
        )
    ):
        return True
    return False


def _looks_like_deterministic_hex_table(candidate: str) -> bool:
    normalized = candidate.lower()
    if re.fullmatch(r"0123456789(?:abcdef){1,2}", normalized):
        return True
    if len(candidate) < 16 or len(candidate) % 2 or not _HEX_DIGEST_RE.fullmatch(candidate):
        return False
    values = [int(candidate[index:index + 2], 16) for index in range(0, len(candidate), 2)]
    return all(right == left + 1 for left, right in zip(values, values[1:]))


def _ip_indicator_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_global:
        return "public"
    return "special"


def _has_network_context(content: str, match_start: int) -> bool:
    start = content.rfind("\n", 0, match_start) + 1
    end = content.find("\n", match_start)
    if end < 0:
        end = len(content)
    return bool(_IP_NETWORK_CONTEXT_RE.search(content[start:end]))


def _extract_context(
    lines: list[str],
    line_no: int,
    radius: int = 2,
    max_line_len: int = 200,
    rules: list[Rule] | None = None,
    source_locations: list[tuple[int, int]] | None = None,
) -> str:
    """
    Build a numbered, multi-line code-context snippet around `line_no`
    (1-indexed) so an analyst can pinpoint the finding in the actual file
    without re-opening it — the matched line plus `radius` lines of
    surrounding context above and below, each capped in width so a single
    minified/huge line doesn't blow out the report.

    This is the difference between an evidence value like just
    "AKIAABCD1234EXAMPLE" and something an analyst can actually act on.
    """
    if not lines:
        return ""
    start = max(1, line_no - radius)
    end = min(len(lines), line_no + radius)
    width = len(str(end))
    out = []
    for i in range(start, end + 1):
        raw = lines[i - 1]
        if len(raw) > max_line_len:
            raw = raw[:max_line_len] + " …(truncated)"
        marker = ">>" if i == line_no else "  "
        if source_locations is not None and i - 1 < len(source_locations):
            string_offset = source_locations[i - 1][0]
            location = f"string {i} @ offset 0x{string_offset:X}"
        else:
            location = str(i).rjust(width)
        out.append(f"{marker} {location} | {raw}")
    return "\n".join(out)


def _binary_byte_offset(
    content: str,
    char_offset: int,
    source_locations: list[tuple[int, int]] | None,
) -> int | None:
    if source_locations is None:
        return None
    line_no = content.count("\n", 0, char_offset) + 1
    line_index = line_no - 1
    if line_index < 0 or line_index >= len(source_locations):
        return None
    line_start = content.rfind("\n", 0, char_offset) + 1
    string_offset, bytes_per_character = source_locations[line_index]
    return string_offset + (char_offset - line_start) * bytes_per_character


def _source_column_number(content: str, char_offset: int) -> int:
    return char_offset - content.rfind("\n", 0, char_offset)


def _looks_like_test_or_example_content(evidence: str) -> bool:
    """
    Detect if evidence is likely from test/example content rather than real credentials.
    This helps reduce false positives in test files, examples, and documentation.
    """
    # Work with isolated value to avoid false positives from variable names
    lowered = _isolate_value(evidence).lower()
    test_indicators = [
        "test", "example", "sample", "demo", "fake", "dummy", "placeholder",
        "changeme", "insert", "your_", "not_real", "invalid", "expired",
        "revoked", "dummy_key", "test_key", "sample_key", "api_key_here",
        "your_api_key", "yourpassword", "put_key_here", "add_key_here", "enter_key_here",
        "password_here", "put_password_here", "enter_password_here",
        "username_here", "put_username_here", "enter_username_here",
        "host_here", "put_host_here", "enter_host_here",
        "db_host", "db_password", "db_username", "connection_string_here",
        "jwt_here", "put_jwt_here", "enter_jwt_here", "token_here",
        "put_token_here", "enter_token_here", "secret_here", "put_secret_here",
        "enter_secret_here", "key_here", "put_key_here", "enter_key_here",
        "todo", "<insert", "<your", "<api", "notreal", "fakekey",
        "demo", "synthetic", "test_only", "not_valid",
    ]

    # Check for common test/example patterns
    for indicator in test_indicators:
        if indicator in lowered:
            return True

    # Check for obvious test patterns like "123456", "abcdefg", etc.
    if re.search(r'^test[\d_]*$', lowered) or re.search(r'^example[\d_]*$', lowered):
        return True

    # Check for sequential patterns that are common in tests
    if len(lowered) >= 4 and (
        lowered == "password" or
        lowered == "passwort" or  # German
        lowered == "motdepasse" or  # French
        lowered == "contraseña" or  # Spanish
        lowered == "123456" or
        lowered == "654321" or
        lowered == "abcdef" or
        lowered == "qwerty" or
        lowered == "letmein" or
        lowered == "monkey" or
        lowered == "dragon" or
        lowered == "baseball" or
        lowered == "iloveyou" or
        lowered == "trustno1" or
        lowered == "welcome" or
        lowered == "admin" or
        lowered == "root" or
        lowered == "guest"
    ):
        return True

    return False


def _validate_jwt_signature(token: str) -> bool:
    """
    Attempt to validate JWT signature if possible without external dependencies.
    This is a basic validation that checks if the token has the correct structure
    and can be decoded (without verifying the signature).
    For production use, consider integrating a cryptography library for actual signature validation.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False

        # Try to decode header and payload
        import base64
        import json

        # Add padding if needed
        header = parts[0]
        payload = parts[1]

        # Base64 URL-safe decode
        header += '=' * (4 - len(header) % 4) if len(header) % 4 else ''
        payload += '=' * (4 - len(payload) % 4) if len(payload) % 4 else ''

        # Decode
        header_decoded = base64.urlsafe_b64decode(header)
        payload_decoded = base64.urlsafe_b64decode(payload)

        # Try to parse as JSON
        json.loads(header_decoded)
        json.loads(payload_decoded)

        return True
    except Exception:
        return False


def _detect_enhanced_cloud_credentials(content: str) -> list[dict]:
    """
    Detect additional cloud credentials beyond the basic YAML rules.
    Returns a list of dictionaries with credential information.
    """
    findings = []

    # Enhanced AWS session tokens
    for match in AWS_SESSION_TOKEN_RE.finditer(content):
        findings.append({
            'type': 'aws_session_token',
            'value': match.group(0),
            'start': match.start(),
            'end': match.end()
        })

    # Enhanced Azure app tokens (JWT tokens that mention azure/microsoft)
    for match in AZURE_APP_TOKEN_RE.finditer(content):
        findings.append({
            'type': 'azure_app_token',
            'value': match.group(0),
            'start': match.start(),
            'end': match.end()
        })

    # Enhanced GCP OAuth tokens
    for match in GCP_OAUTH_TOKEN_RE.finditer(content):
        findings.append({
            'type': 'gcp_oauth_token',
            'value': match.group(0),
            'start': match.start(),
            'end': match.end()
        })

    return findings


def _confidence_for(evidence: str, base: str = "Medium") -> str:
    if _looks_like_placeholder(evidence):
        return "Low"
    if _looks_like_test_or_example_content(evidence):
        return "Low"
    score = 0
    value = _isolate_value(evidence)

    # Length scoring
    if len(value) >= 8:
        score += 1
    if len(value) >= 12:
        score += 1
    if len(value) >= 16:
        score += 1
    if len(value) >= 24:
        score += 1

    # Character diversity scoring
    has_digit = any(c.isdigit() for c in value)
    has_letter = any(c.isalpha() for c in value)
    has_special = any(not c.isalnum() for c in value)

    if has_digit and has_letter:
        score += 1
    if has_special:
        score += 1

    # Penalize excessive repetition of same character
    if len(value) > 0:
        if len(set(value)) == 1:  # All same character
            score -= 2
        elif len(set(value)) < min(5, len(value) // 2):  # Very low diversity
            score -= 1

    if score >= 5:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"


def _b64url_json(part: str) -> dict:
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="ignore"))


def _jwt_findings(
    content: str,
    file_path: str,
    lines: list[str],
    rules: list[Rule] | None = None,
    source_locations: list[tuple[int, int]] | None = None,
) -> list[Finding]:
    findings = []
    for match in JWT_RE.finditer(content):
        token = match.group(0)
        try:
            header = _b64url_json(token.split(".")[0])
            payload = _b64url_json(token.split(".")[1])
        except Exception:
            continue
        line_no = content.count("\n", 0, match.start()) + 1
        interesting = {k: payload.get(k) for k in ("exp", "iss", "aud", "roles", "role", "scp") if k in payload}

        # Determine confidence based on JWT validation and expiration
        confidence = "High"
        if "exp" in payload:
            try:
                import time
                exp_timestamp = payload["exp"]
                if isinstance(exp_timestamp, (int, float)) and exp_timestamp < time.time():
                    # Expired token
                    confidence = "Low"
                elif not _validate_jwt_signature(token):
                    # Invalid structure
                    confidence = "Medium"
            except Exception:
                # If we can't parse expiration, keep original confidence logic
                pass
        else:
            confidence = "Medium"

        findings.append(Finding(
            module="secrets",
            rule_id="jwt-token",
            title="JWT token embedded in file",
            severity=Severity.HIGH if "exp" in payload else Severity.MEDIUM,
            file_path=file_path,
            evidence=token,
            description="A JSON Web Token was found and decoded successfully. Embedded JWTs can grant direct access until expiry and may expose issuer, audience, and role claims.",
            remediation="Remove embedded JWTs, rotate/revoke the token, and issue short-lived tokens at runtime through an authenticated flow.",
            poc=_build_text_poc(file_path, line_no, "jwt-token", token),
            line_number=line_no,
            column_number=_source_column_number(content, match.start()),
            offset=_binary_byte_offset(content, match.start(), source_locations),
            tags=["jwt", "token", "auth"],
            confidence=confidence,
            extra={
                "jwt": {"header": header, "payload": payload, "alg": header.get("alg"), **interesting},
                "context": _extract_context(
                    lines, line_no, rules=rules, source_locations=source_locations
                ),
            },
        ))
    return findings


def _parse_db_uri(uri: str) -> dict:
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "database": parsed.path.lstrip("/") or None,
        "username": unquote(parsed.username) if parsed.username else None,
        "password": unquote(parsed.password) if parsed.password else None,
        "ssl": query.get("sslmode", query.get("ssl", query.get("encrypt", [None])))[0],
    }


def _db_uri_findings(
    content: str,
    file_path: str,
    lines: list[str],
    rules: list[Rule] | None = None,
    source_locations: list[tuple[int, int]] | None = None,
) -> list[Finding]:
    findings = []
    for match in DB_URI_RE.finditer(content):
        uri = match.group(0).rstrip("),.;")
        try:
            parsed = _parse_db_uri(uri)
        except Exception:
            continue
        line_no = content.count("\n", 0, match.start()) + 1
        findings.append(Finding(
            module="secrets",
            rule_id="database-connection-string",
            title="Database connection string exposed",
            severity=Severity.HIGH if parsed.get("password") else Severity.MEDIUM,
            file_path=file_path,
            evidence=uri,
            description="A database connection string was found and parsed into host, port, database, username, password, and SSL-related fields.",
            remediation="Move database connection settings to a secret store, rotate exposed credentials, and require TLS for database connections.",
            poc=_build_text_poc(file_path, line_no, "database-connection-string", uri),
            line_number=line_no,
            column_number=_source_column_number(content, match.start()),
            offset=_binary_byte_offset(content, match.start(), source_locations),
            tags=["database", "connection-string", "credential"],
            confidence="High" if parsed.get("password") and parsed.get("host") else "Medium",
            extra={
                "database_connection": parsed,
                "context": _extract_context(
                    lines, line_no, rules=rules, source_locations=source_locations
                ),
            },
        ))
    return findings


def _correlate_related_secrets(findings: list[Finding]) -> list[Finding]:
    by_file_line: dict[tuple[str, int], dict[str, Finding]] = {}
    assigned_findings: set[str] = set()  # Track fingerprints of findings already assigned
    for f in findings:
        source_line = f.line_number or f.extra.get("extracted_string_index")
        if f.module != "secrets" or not source_line:
            continue
        if f.rule_id in {"database-connection-string", "jwt-token", "correlated-secret-bundle"}:
            continue
        # Skip low-confidence findings as they shouldn't contribute to high-confidence correlations
        if f.confidence == "Low":
            continue
        blob = f"{f.rule_id} {f.title} {f.evidence}".lower()
        for kind, markers in CORRELATION_KEYS.items():
            if any(m in blob for m in markers):
                # Only assign this finding to one category to prevent one finding from fulfilling multiple roles
                f_fingerprint = f.fingerprint()
                if f_fingerprint not in assigned_findings:
                    by_file_line.setdefault((f.file_path, source_line), {})[kind] = f
                    assigned_findings.add(f_fingerprint)
                    break  # Assign to first matching category only
    correlated = []
    consumed = set()
    for (_file, _line), parts in by_file_line.items():
        if len(parts) < 2 or not ({"password", "api_key"} & set(parts)):
            continue
        seed = next(iter(parts.values()))
        evidence = "; ".join(f"{kind}={f.evidence}" for kind, f in parts.items())
        correlated.append(Finding(
            module="secrets",
            rule_id="correlated-secret-bundle",
            title="Correlated credential bundle exposed",
            severity=Severity.HIGH,
            file_path=seed.file_path,
            evidence=evidence,
            description="Multiple related credential indicators appear together and are reported as one correlated secret bundle.",
            remediation="Rotate all related credentials together and move the complete connection profile into a managed secrets store.",
            line_number=seed.line_number,
            column_number=seed.column_number,
            offset=seed.offset,
            tags=["credential", "correlated", "secret-bundle"]
            + (["embedded-in-binary"] if "embedded-in-binary" in seed.tags else []),
            confidence="High",
            extra={
                "components": sorted(parts.keys()),
                "context": seed.extra.get("context", ""),
                **(
                    {"extracted_string_index": seed.extra["extracted_string_index"]}
                    if "extracted_string_index" in seed.extra else {}
                ),
            },
        ))
        consumed.update(f.fingerprint() for f in parts.values())
    return [f for f in findings if f.fingerprint() not in consumed] + correlated


def _build_text_poc(file_path: str, line_no: int, rule_id: str, evidence: str) -> str:
    """Build a reproducible, analyst-ready PoC block for a text/config-file match."""
    filename = Path(file_path).name
    return (
        f"1. Open the file directly:\n"
        f"     {file_path}\n"
        f"   and go to line {line_no}.\n\n"
        f"2. Reproduce the detection independently:\n"
        f"   Windows (PowerShell):\n"
        f"     Select-String -Path \"{file_path}\" -Pattern \"{rule_id}\" -SimpleMatch:$false\n"
        f"   Linux/macOS:\n"
        f"     grep -n -i '{rule_id}' \"{file_path}\"\n\n"
        f"3. Confirm exploitability: if this is a live/production credential, attempt "
        f"authentication against the associated service using the value found at "
        f"line {line_no} of {filename} (in an authorized test window only) to "
        f"confirm it is active before including it as a confirmed finding rather "
        f"than a potential one.\n\n"
        f"4. Matched evidence: {evidence}\n\n"
        f"5. Evidence capture for the report: screenshot the line in context."
    )


def _build_entropy_poc(file_path: str, line_no: int, evidence: str) -> str:
    return (
        f"1. Open {file_path} at line {line_no} and manually inspect the "
        f"high-entropy token in context — entropy scoring flags candidates, "
        f"it does not confirm they are secrets.\n\n"
        f"2. Cross-reference the token format against known credential patterns "
        f"(length, charset, prefix) to identify the likely secret type (API key, "
        f"session token, encryption key, etc.).\n\n"
        f"3. If it resembles a live credential, test it against the likely "
        f"issuing service in an authorized test window to confirm activity "
        f"before escalating severity in the final report.\n\n"
        f"4. Evidence for this finding: {evidence}"
    )


def _build_binary_poc(file_path: str, evidence: str) -> str:
    filename = Path(file_path).name
    return (
        f"1. Extract printable strings from the binary directly to confirm "
        f"independently:\n"
        f"   Windows (Sysinternals strings.exe):\n"
        f"     strings64.exe -n 6 \"{file_path}\"\n"
        f"   Linux:\n"
        f"     strings -n 6 \"{file_path}\"\n\n"
        f"2. Open {filename} in a PE viewer (CFF Explorer, Detect It Easy, or "
        f"IDA/Ghidra) and locate the string in the resource/data section to "
        f"confirm it is not dead code or a leftover debug string.\n\n"
        f"3. If confirmed live, treat this the same as a config-file secret: "
        f"rotate the credential and remove it from the compiled binary — "
        f"hardcoded strings in compiled code are trivially recoverable with "
        f"basic reverse-engineering tools regardless of packing.\n\n"
        f"4. Matched evidence: {evidence}"
    )


def _build_permission_poc(file_path: str) -> str:
    return (
        f"1. Confirm the permissive ACL directly:\n"
        f"   Windows:\n"
        f"     icacls \"{file_path}\"\n"
        f"   Linux/macOS:\n"
        f"     ls -l \"{file_path}\"\n\n"
        f"2. As a low-privileged local user (not administrator), attempt to "
        f"write to the file to confirm exploitability:\n"
        f"   Windows (PowerShell):\n"
        f"     Add-Content -Path \"{file_path}\" -Value \"poc-write-test\"\n"
        f"   Linux/macOS:\n"
        f"     echo poc-write-test >> \"{file_path}\"\n\n"
        f"3. If the write succeeds under a non-privileged account, this "
        f"confirms a low-privileged user can tamper with or exfiltrate the "
        f"secrets identified in this file. Revert the test write before "
        f"closing out the finding."
    )


_SQL_KEYWORD_NOISE = {
    "select", "database", "connectionstring", "where", "from", "insert", "update",
    "delete", "exec", "execute", "procedure", "initial", "table", "into", "values",
    "declare", "begin", "end", "driver", "server", "provider",
}


def _looks_like_sql_noise(evidence_raw: str) -> bool:
    """
    Rejects password/PWD= matches whose captured "value" is actually an
    adjacent SQL keyword or ALL_CAPS_IDENTIFIER rather than a real
    credential (e.g. "PWD= SELECT", "PWD=      SM.MAJOR_VERSION"). This
    happens because a password-assignment regex has no way to know
    where a real assignment's value ends versus unrelated text that
    happens to sit right after it in string-extracted, SQL-heavy legacy
    code — it can only bound the value syntactically, not semantically.
    """
    value_match = re.search(r"[:=]\s*[\"']?([^\"']+?)[\"']?\s*$", evidence_raw)
    value = (value_match.group(1) if value_match else evidence_raw).strip()
    if not value:
        return True
    low = value.lower().rstrip(";")
    if low in _SQL_KEYWORD_NOISE:
        return True
    # A qualified SQL identifier like "SM.MAJOR_VERSION" or a bracketed
    # table/column reference like "fortuneNextAssembly.mdb]...": real
    # passwords essentially never contain a literal "." followed by an
    # ALL_CAPS or bracket-qualified continuation.
    if "." in value and re.search(r"\.[A-Z_\]]{3,}", value):
        return True
    # Bare ALL_CAPS_WITH_UNDERSCORES identifier and nothing else — a
    # column/constant name, not a credential (real passwords mix case
    # or include non-alpha characters far more often than not).
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", value):
        return True
    return False


def _scan_text_content(
    content: str,
    file_path: str,
    rules: list[Rule],
    enable_entropy: bool,
    source_locations: list[tuple[int, int]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    matched_evidence: list[str] = []
    lines = content.splitlines()

    # --- Regex rule matches, tracked with line numbers ---
    for rule in rules:
        for match in rule.finditer(content):
            evidence_raw = match.group(0)
            if _looks_like_regex_definition(evidence_raw):
                # This match is a regex pattern literal (e.g. a rule
                # definition inside a rules/*.yaml-style file), not an
                # actual hardcoded credential — see _looks_like_regex_definition.
                continue
            if rule.id == "hardcoded-ip" and is_version_attribute_context(content, match.start()):
                # Dotted-quad version numbers (PE VERSIONINFO, embedded
                # manifest assemblyIdentity/dependency version="6.0.0.0",
                # .NET AssemblyVersion, etc.) are structurally identical to
                # an IPv4 address. If the text right before this match is a
                # version="/Version:/FileVersion= style attribute, this is
                # a declared version number, not a network indicator.
                continue
            address_scope = None
            if rule.id == "hardcoded-ip":
                address_scope = _ip_indicator_scope(evidence_raw.strip())
                if address_scope == "invalid":
                    continue
                if (
                    source_locations is not None
                    and address_scope != "loopback"
                    and not _has_network_context(content, match.start())
                ):
                    continue
            if rule.id in ("generic-password-assignment", "odbc-pwd") and _looks_like_sql_noise(evidence_raw):
                # A password/PWD= regex has no way to know where a real
                # assignment's value ends versus adjacent unrelated text —
                # in string-extracted binary/SQL-heavy code, "PWD=" is
                # frequently immediately followed (in the raw extracted
                # byte stream, not in any real source construct) by the
                # next unrelated SQL keyword/identifier ("PWD= SELECT",
                # "PWD=      SM.MAJOR_VERSION"). Reject values that look
                # like SQL keywords or ALL_CAPS_IDENTIFIERS rather than an
                # actual credential.
                continue
            line_no = content.count("\n", 0, match.start()) + 1
            severity = rule.severity
            title = rule.description
            description = (
                f"Pattern matching rule '{rule.id}' ({rule.description}) "
                "was found in this file."
            )
            confidence = _confidence_for(evidence_raw)
            remediation = (
                "Remove hardcoded credentials/secrets from source and "
                "configuration files. Use a secrets manager (Azure Key "
                "Vault, AWS Secrets Manager, HashiCorp Vault) or environment "
                "variables injected at runtime, and rotate the exposed "
                "credential immediately."
            )
            poc = _build_text_poc(file_path, line_no, rule.id, evidence_raw)
            extra = {
                "context": _extract_context(
                    lines, line_no, rules=rules, source_locations=source_locations
                )
            }
            if rule.id == "hardcoded-ip":
                severity = Severity.INFO if address_scope == "loopback" else Severity.LOW
                title = (
                    "Loopback IPv4 configuration indicator"
                    if address_scope == "loopback"
                    else "Embedded IPv4 address indicator"
                )
                confidence = "High"
                description = (
                    f"This static string is a {address_scope} IPv4 address. "
                    "Its presence alone does not establish that the application "
                    "connects to it or that the address is vulnerable. Loopback "
                    "addresses refer to the local host."
                )
                remediation = (
                    "Confirm whether this address is an intentional endpoint for "
                    "the supported deployment. Move environment-specific values "
                    "to configuration when appropriate; retain intentional "
                    "loopback addresses for local-only services or IPC."
                )
                ip_offset = _binary_byte_offset(
                    content, match.start(), source_locations
                )
                location = (
                    f"near byte offset 0x{ip_offset:X}"
                    if ip_offset is not None
                    else f"at line {line_no}"
                )
                poc = (
                    "Static verification:\n"
                    f"  1. Locate the IPv4 literal in '{Path(file_path).name}' "
                    f"{location}.\n"
                    "  2. Review the surrounding resource/configuration and, if "
                    "available, the source or decompiled call site to establish "
                    "whether it is used as a network endpoint.\n"
                    "  3. A static address alone does not establish a connection "
                    "or vulnerability. Treat loopback values as local indicators; "
                    "do not probe external addresses without authorization."
                )
                extra["ip_scope"] = address_scope
            findings.append(
                Finding(
                    module="secrets",
                    rule_id=rule.id,
                    title=title,
                    severity=severity,
                    file_path=file_path,
                    evidence=evidence_raw,
                    description=description,
                    remediation=remediation,
                    poc=poc,
                    line_number=line_no,
                    column_number=_source_column_number(content, match.start()),
                    offset=_binary_byte_offset(content, match.start(), source_locations),
                    tags=rule.tags,
                    confidence=confidence,
                    extra=extra,
                )
            )
            matched_evidence.append(evidence_raw)

    findings.extend(_jwt_findings(content, file_path, lines, rules, source_locations))
    findings.extend(_db_uri_findings(content, file_path, lines, rules, source_locations))

    # --- Entropy-based catch-all for secrets with no known pattern ---
    if enable_entropy:
        for candidate, offset in find_high_entropy_candidates(content):
            # Skip candidates already captured by a regex rule to avoid duplicate
            # noise for the same underlying string — substring-based, not just
            # exact-match, since a regex rule often captures the whole
            # "key=VALUE" assignment while the entropy scanner isolates just
            # the VALUE token (or vice versa), which is still the same secret.
            if any(candidate in evidence or evidence in candidate for evidence in matched_evidence):
                continue
            if _looks_like_placeholder(candidate):
                continue
            if _entropy_candidate_has_benign_context(candidate, content, offset):
                continue
            line_no = content.count("\n", 0, offset) + 1
            findings.append(
                Finding(
                    module="secrets",
                    rule_id="high-entropy-string",
                    title="Unclassified high-entropy string",
                    severity=Severity.LOW,
                    file_path=file_path,
                    evidence=candidate,
                    description=(
                        "A string scored above the entropy threshold, but entropy "
                        "alone does not establish that it is a credential. Review "
                        "the surrounding context and verify any suspected secret "
                        "through an independent identifier or application-specific "
                        "evidence."
                    ),
                    remediation=(
                        "Manually review this value. If it is a credential or "
                        "token, remove it from the file, rotate it, and load it "
                        "via a secrets manager or environment variable instead."
                    ),
                    line_number=line_no,
                    column_number=_source_column_number(content, offset),
                    offset=_binary_byte_offset(content, offset, source_locations),
                    tags=["entropy", "generic"],
                    confidence="Low",  # entropy hits are inherently noisier
                    poc=_build_entropy_poc(file_path, line_no, candidate),
                    extra={
                        "context": _extract_context(
                            lines, line_no, rules=rules, source_locations=source_locations
                        )
                    },
                )
            )

    return findings


def _config_intel_findings(path: Path, rules: list[Rule] | None = None) -> list[Finding]:
    findings = []
    for setting in extract_interesting_settings(path):
        value = setting["value"]
        key = setting["key"]
        sensitive = any(t in setting["tags"] for t in ("auth-setting", "database-setting"))
        findings.append(Finding(
            module="secrets",
            rule_id="config-intelligence-setting",
            title=f"{setting['format']} configuration exposes security-relevant setting",
            severity=Severity.MEDIUM if sensitive else Severity.LOW,
            file_path=str(path),
            evidence=f"{key}={value}",
            description="Warden parsed this configuration file and identified an authentication, database, logging, TLS, or debug setting.",
            remediation="Review this setting for production safety. Keep secrets out of config files, disable debug mode, enforce TLS verification, and avoid verbose sensitive logging.",
            tags=["config-intelligence"] + setting["tags"],
            confidence="Medium",
            extra={"config": setting},
        ))
    return findings


def _scan_pe_strings(
    pe_path: Path,
    rules: list[Rule],
    enable_entropy: bool,
) -> list[Finding]:
    """Extract embedded strings from a PE file and run the same rule engine."""
    findings: list[Finding] = []
    try:
        data = pe_path.read_bytes()
    except OSError:
        return findings

    strings_with_offsets = extract_strings_from_bytes(data)
    if not strings_with_offsets:
        return findings

    # Concatenate extracted strings with newline separators so the same
    # line-based regex scanning logic can run unmodified against binary
    # content while retaining each string's byte offset and encoding width.
    joined = "\n".join(s for s, _ in strings_with_offsets)
    source_locations = [
        (offset, 2 if offset + 1 < len(data) and data[offset + 1] == 0 else 1)
        for _, offset in strings_with_offsets
    ]
    text_findings = _scan_text_content(
        joined,
        str(pe_path),
        rules,
        enable_entropy,
        source_locations=source_locations,
    )

    # A build/product version number ("6.0.0.0", "19.0.3.0") is
    # structurally identical to a dotted-quad IPv4 address, and PE
    # binaries always embed their own version as a plain string somewhere
    # — this is the single most common false positive for the
    # hardcoded-ip rule. Drop any match that exactly equals a version
    # string this specific binary actually declares in its own
    # VERSIONINFO resource, rather than guessing from the digits alone.
    version_strings = get_version_strings(pe_path)
    if version_strings:
        text_findings = [
            f for f in text_findings
            if not (
                f.rule_id == "hardcoded-ip"
                and f.evidence.strip() in version_strings
            )
        ]

    # Re-map line-number placeholders to byte offsets where possible, and
    # tag these findings as binary-origin for the report.
    for f in text_findings:
        f.tags = list(set(f.tags + ["embedded-in-binary"]))
        f.description += " (Extracted from embedded strings inside a PE binary.)"
        if f.rule_id == "hardcoded-ip":
            offset_note = (
                f"byte offset 0x{f.offset:X}"
                if f.offset is not None
                else "the matching embedded string"
            )
            f.poc = (
                "Static verification:\n"
                f"  1. Inspect {offset_note} in a PE/string viewer and review "
                "the complete containing string.\n"
                "  2. Review source or decompiled call sites to establish "
                "whether the value is used as a network endpoint.\n"
                "  3. A static address alone does not establish a connection "
                "or vulnerability. Treat loopback values as local indicators; "
                "do not probe external addresses without authorization."
            )
        else:
            f.poc = _build_binary_poc(str(pe_path), f.evidence)
        if f.line_number is not None:
            f.extra["extracted_string_index"] = f.line_number
            f.line_number = None
    findings.extend(text_findings)

    return findings


def _flag_permissions(path: Path, related_findings: list[Finding]) -> list[Finding]:
    """If a file has sensitive findings, also check/report its permissions."""
    if not related_findings:
        return []

    perm_info = check_permissive_permissions(path)
    findings: list[Finding] = []

    if perm_info.get("world_writable"):
        findings.append(
            Finding(
                module="secrets",
                rule_id="world-writable-sensitive-file",
                title="World-writable file containing sensitive data",
                severity=Severity.HIGH,
                file_path=str(path),
                evidence="File permission bits include world-write (o+w)",
                description=(
                    "This file contains one or more detected secrets/credentials "
                    "and is writable by any local user, allowing tampering or "
                    "credential theft by a low-privileged local account."
                ),
                remediation=(
                    "Restrict file ACLs so only the application's service "
                    "account and administrators have write access."
                ),
                tags=["permissions", "acl"],
                confidence="Medium",
                poc=_build_permission_poc(str(path)),
            )
        )

    if perm_info.get("note") and perm_info["platform_checked"] == "Windows":
        # Informational: analyst should follow up with icacls on Windows hosts.
        findings.append(
            Finding(
                module="secrets",
                rule_id="acl-check-limited",
                title="ACL inspection limited on this platform",
                severity=Severity.INFO,
                file_path=str(path),
                evidence=perm_info["note"],
                description="Static ACL review was limited; verify manually.",
                remediation="Run `icacls <file>` on the target Windows host to confirm effective permissions.",
                tags=["permissions", "acl", "gap"],
                confidence="Low",
            )
        )

    return findings


def run(
    target_dir: str | Path,
    rules_dir: str | Path | None = None,
    enable_entropy: bool = True,
    scan_pe_strings: bool = True,
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
    scan_cache: ScanCache | None = None,
    max_workers: int = 1,
) -> list[Finding]:
    """
    Entry point for Module 1. Walks `target_dir`, scans every eligible file,
    and returns a deduplicated list of Finding objects.

    Args:
        target_dir: root directory of the extracted/installed application.
        rules_dir: optional override directory for YAML rule packs.
        enable_entropy: toggle entropy-based catch-all detection.
        scan_pe_strings: toggle embedded-string scanning of .exe/.dll files.
        single_file: if given, restrict the scan to exactly this one file
            instead of walking target_dir.
        progress_callback: optional callable(file_path: str) invoked per file,
            for CLI progress reporting.
        error_callback: optional callable(message: str) invoked when a single
            file fails to scan (corrupt/unreadable/unexpected format) — the
            file is skipped and the scan continues rather than aborting the
            whole module and losing every finding already collected.
    """
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None
    rules = load_rules(Path(rules_dir) if rules_dir else None, warn=error_callback)

    all_findings: list[Finding] = []
    seen_fingerprints: set[str] = set()

    def _add(findings: list[Finding]):
        for f in findings:
            fp = f.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(f)

    def _scan_path(path: Path) -> tuple[Path, list[Finding]]:
        if scan_cache and scan_cache.unchanged(path, "secrets"):
            return path, []
        if progress_callback:
            progress_callback(str(path))

        try:
            kind = classify_file(path)
            file_findings: list[Finding] = []

            if kind == "text":
                content = read_text_safely(path)
                if content:
                    file_findings = _scan_text_content(content, str(path), rules, enable_entropy)
                    file_findings.extend(_config_intel_findings(path, rules))

            elif kind == "pe" and scan_pe_strings and is_pe_file(path):
                file_findings = _scan_pe_strings(path, rules, enable_entropy)

            elif kind == "db":
                # v1: sniff raw bytes for plaintext PII/credential patterns only;
                # no structured DB parsing (SQLite page format, Access JET) yet.
                try:
                    raw = path.read_bytes()[: 20 * 1024 * 1024]
                    content = raw.decode("utf-8", errors="ignore")
                except OSError:
                    content = ""
                if content:
                    file_findings = _scan_text_content(content, str(path), rules, enable_entropy)
                    file_findings.extend(_config_intel_findings(path, rules))
                    for f in file_findings:
                        f.tags = list(set(f.tags + ["local-database"]))

            if file_findings:
                file_findings = _correlate_related_secrets(file_findings)
                file_findings.extend(_flag_permissions(path, file_findings))
            if scan_cache:
                scan_cache.mark_scanned(path, "secrets", sha256_file(path))
            return path, file_findings
        except Exception as e:
            # One malformed/unreadable file must never wipe out every
            # finding already collected from the rest of the scan.
            if error_callback:
                error_callback(f"secrets: skipped '{path}' after error: {e}")
            return path, []

    paths = list(iter_target_files(target_dir, single_file=single_file))
    if max_workers and max_workers > 1 and len(paths) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_scan_path, path) for path in paths]
            for future in as_completed(futures):
                _path, file_findings = future.result()
                _add(file_findings)
    else:
        for path in paths:
            _path, file_findings = _scan_path(path)
            _add(file_findings)

    return all_findings
