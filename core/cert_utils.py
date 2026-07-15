"""
Lightweight X.509 certificate analysis for bundled certificate files found
on a Linux or macOS target (PEM/DER .crt, .cer, .pem files) — flags
self-signed, expired, and weak-signature-algorithm certificates.

This is deliberately independent from signature_module.py's Authenticode
handling (WIN_CERTIFICATE/PKCS#7 parsing is Windows-PE-specific); this
module only deals with standalone certificate files bundled inside a
Linux/macOS application's install tree, which is a different artifact
class entirely, so it does not modify or depend on the Windows module.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

WEAK_SIGNATURE_ALGORITHMS = {"sha1", "md5"}

CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".cert"}


@dataclass
class CertFinding:
    path: str
    subject_cn: str = "unknown"
    issuer_cn: str = "unknown"
    not_valid_after: Optional[datetime] = None
    is_expired: bool = False
    is_self_signed: bool = False
    is_ca_certificate: bool = False
    signature_algorithm: str = "unknown"
    is_weak_algorithm: bool = False
    error: Optional[str] = None


# Well-known system/vendor CA bundle filenames. These are large collections
# of legitimate root CAs (Mozilla/curl/OS trust stores) that are *expected*
# to be self-signed by design — scanning them as if they were an
# application's own certificate produces pure noise, not findings.
KNOWN_CA_BUNDLE_NAMES = {
    "ca-bundle.crt", "ca-certificates.crt", "cacert.pem", "cacerts",
    "cert.pem", "curl-ca-bundle.crt",
}


def _load_certificate(data: bytes):
    try:
        return x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data, default_backend())
    except ValueError:
        return None


def _cn(name) -> str:
    try:
        attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else str(name)
    except Exception:
        return str(name)


def analyze_certificate_file(path: Path) -> CertFinding:
    """Parse a single certificate file (PEM or DER) and flag common issues."""
    result = CertFinding(path=str(path))

    if path.name.lower() in KNOWN_CA_BUNDLE_NAMES:
        result.error = "Recognized system/vendor CA trust bundle — skipped (not an application certificate)"
        return result

    try:
        data = path.read_bytes()
    except OSError as e:
        result.error = f"Could not read file: {e}"
        return result

    cert = _load_certificate(data)
    if cert is None:
        result.error = "File does not contain a parseable X.509 certificate"
        return result

    result.subject_cn = _cn(cert.subject)
    result.issuer_cn = _cn(cert.issuer)
    result.signature_algorithm = (cert.signature_hash_algorithm.name
                                  if cert.signature_hash_algorithm else "unknown")
    result.is_weak_algorithm = result.signature_algorithm.lower() in WEAK_SIGNATURE_ALGORITHMS

    # Full Name (all RDNs) equality, not just Common Name — two distinct
    # certs can legitimately share a CN (e.g. a wildcard reused across
    # intermediate + leaf test fixtures) without being self-signed, and
    # relying on CN alone both under- and over-detects.
    result.is_self_signed = cert.subject == cert.issuer

    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        result.is_ca_certificate = bool(ext.value.ca)
    except x509.ExtensionNotFound:
        result.is_ca_certificate = False

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:  # older `cryptography` versions
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    result.not_valid_after = not_after
    result.is_expired = not_after < datetime.now(timezone.utc)

    return result
