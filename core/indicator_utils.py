"""
Shared, false-positive-aware extraction helpers for URLs/IPs/emails/API
endpoints pulled from binary strings and config/text content.

Used by linux_module.py and macos_module.py. Centralized here (rather than
duplicated per-module) so a false-positive fix applies to both platforms at
once, and so binary-string noise doesn't inflate "Network Artifact
Discovery" or "Binary Analysis" findings with junk that isn't a real
security-relevant indicator.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Matches immediately-preceding context like `version="`, `Version:`,
# `FileVersion=`, `assemblyIdentity ... version='` — i.e. the match is the
# *value* of a version attribute/field, not a standalone network address.
# This is the manifest/XML equivalent of the PE-VERSIONINFO cross-check:
# embedded application manifests (assemblyIdentity, dependency entries for
# things like "Microsoft.Windows.Common-Controls") declare a
# `version="6.0.0.0"` attribute on almost every Windows PE, and that number
# is structurally identical to a dotted-quad IPv4 address. Checking the
# textual context right before a match is more general than cross-checking
# against a single VERSIONINFO resource, since it also catches manifest XML,
# .NET AssemblyVersion attributes, and similar version declarations that
# don't come from VERSIONINFO at all.
_VERSION_CONTEXT_RE = re.compile(
    r"(?:version|fileversion|productversion|assemblyversion|schemaversion)\s*[:=]\s*[\"']?$",
    re.IGNORECASE,
)


def is_version_attribute_context(text: str, match_start: int, lookback: int = 40) -> bool:
    """True if the text immediately before `match_start` looks like a
    `version="` / `Version:` / `FileVersion=` style attribute assignment —
    meaning the dotted-quad number at `match_start` is a declared version
    number, not a real network indicator."""
    prefix = text[max(0, match_start - lookback):match_start]
    return bool(_VERSION_CONTEXT_RE.search(prefix))


URL_RE = re.compile(r"https?://[^\s\"'<>]{4,300}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
API_ENDPOINT_RE = re.compile(r"/(?:api|v[0-9]+|rest)/[a-zA-Z0-9_/\-{}]{2,100}")

# Hostnames/domains that are boilerplate noise in almost every binary
# (XML schemas, license headers, package-manager namespaces, standard
# library URLs) rather than a genuine attack-surface/network indicator.
# Denylisted at the *domain* level, not by substring, to avoid the "test."
# matching "latest.com" class of bug.
BOILERPLATE_DOMAINS = {
    "w3.org", "xmlpull.org", "xmlsoap.org", "schemas.android.com",
    "gnu.org", "apache.org", "opensource.org", "creativecommons.org",
    "purl.org", "json-schema.org", "schemas.microsoft.com",
    "registry.npmjs.org", "pypi.org", "golang.org", "go.dev",
    "docs.python.org", "developer.android.com", "developer.apple.com",
    "github.com", "sourceforge.net",
    "localhost.localdomain",
}

# Placeholder/sample email domains that generate noise, not real findings.
PLACEHOLDER_EMAIL_DOMAINS = {"example.com", "example.org", "test.com", "domain.com", "email.com"}

# Internal/dev/staging host markers, matched against the *parsed hostname*
# (or its labels) — never as a raw substring of the full URL, which is what
# previously caused "test." to false-positive-match inside "latest.com".
INTERNAL_HOST_EXACT_OR_PREFIX = ("localhost", "127.0.0.1", "0.0.0.0")
INTERNAL_HOST_LABELS = {"dev", "development", "stage", "staging", "test", "testing",
                         "internal", "corp", "local", "sandbox", "qa", "uat"}
PRIVATE_IP_PREFIXES = ("10.", "192.168.", "169.254.")
# 172.16.0.0 - 172.31.255.255
_PRIVATE_172_RE = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")


def is_valid_ipv4(candidate: str) -> bool:
    """Reject numeric look-alikes (version strings like 999.1.2.3, or
    build numbers) that the loose \\d{1,3} regex would otherwise accept —
    each octet must be a real 0-255 byte value."""
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 and (part == "0" or not part.startswith("0")) for part in parts)


def is_private_or_internal_ip(ip: str) -> bool:
    return ip.startswith(INTERNAL_HOST_EXACT_OR_PREFIX) or ip.startswith(PRIVATE_IP_PREFIXES) or bool(_PRIVATE_172_RE.match(ip))


def _registrable_domain(hostname: str) -> str:
    """Best-effort last-two-labels extraction (e.g. 'api.staging.acme.com'
    -> 'acme.com'), good enough for a denylist check without a full public
    suffix list dependency."""
    labels = hostname.lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()


def extract_urls(text: str, max_results: int = 15) -> list[str]:
    """Extract URLs, deduplicated, with obvious boilerplate/schema/license
    URLs filtered out so they don't drown out real attack-surface hits."""
    seen: list[str] = []
    for url in URL_RE.finditer(text):
        candidate = url.group(0).rstrip(".,;)\"'")
        try:
            host = urlparse(candidate).hostname or ""
        except ValueError:
            continue
        if not host:
            continue
        if _registrable_domain(host) in BOILERPLATE_DOMAINS:
            continue
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) >= max_results:
            break
    return seen


def filter_out_version_strings(ips: list[str], version_strings: set[str]) -> list[str]:
    """
    Drop any dotted-quad "IP" that exactly matches a version string the
    same binary actually declares in its own VERSIONINFO resource (e.g.
    "6.0.0.0", "19.0.3.0", "10.60.20.0"). A build/product version number
    is structurally identical to an IPv4 address — both are four
    dot-separated 0-255 numbers — so this is the single most common
    false-positive source for IP extraction against PE binaries, and the
    fix is to check against the specific version string(s) this binary
    itself declares, not to guess from the digits alone.
    """
    if not version_strings:
        return ips
    return [ip for ip in ips if ip not in version_strings]


def extract_ips(text: str, max_results: int = 15) -> list[str]:
    seen: list[str] = []
    for m in IPV4_RE.finditer(text):
        candidate = m.group(0)
        if not is_valid_ipv4(candidate):
            continue
        # Skip common non-indicator numeric patterns: version-like strings
        # embedded right before/after a letter (e.g. "libfoo.so.1.2.3.4"),
        # loopback netmask noise, and all-zero addresses.
        if candidate in ("0.0.0.0", "255.255.255.255"):
            continue
        if is_version_attribute_context(text, m.start()):
            continue
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) >= max_results:
            break
    return seen


def extract_emails(text: str, max_results: int = 10) -> list[str]:
    seen: list[str] = []
    for m in EMAIL_RE.finditer(text):
        candidate = m.group(0)
        domain = candidate.rsplit("@", 1)[-1].lower()
        if domain in PLACEHOLDER_EMAIL_DOMAINS:
            continue
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) >= max_results:
            break
    return seen


def extract_api_endpoints(text: str, max_results: int = 10) -> list[str]:
    seen: list[str] = []
    for m in API_ENDPOINT_RE.finditer(text):
        candidate = m.group(0)
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) >= max_results:
            break
    return seen


def classify_internal_host(url: str) -> bool:
    """True if `url`'s *hostname* (not the raw string) looks internal/dev/
    staging/private. Matches on parsed hostname labels and IP prefixes only
    — never a substring check against the full URL — to avoid false
    positives like 'test.' matching inside 'latest.com'."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host.startswith(INTERNAL_HOST_EXACT_OR_PREFIX):
        return True
    if is_valid_ipv4(host) and is_private_or_internal_ip(host):
        return True
    labels = host.split(".")
    return any(label in INTERNAL_HOST_LABELS for label in labels)
