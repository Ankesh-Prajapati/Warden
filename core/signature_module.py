"""
Module 3 — Signature / Integrity Check.

Covers, per the project spec:
  - Authenticode signature presence check on every .exe/.dll
  - Structural certificate parsing: expired certs, self-signed certs,
    weak signature algorithms (SHA-1/MD5)
  - Cross-binary publisher consistency (supply-chain inconsistency signal)
  - Optional deeper verification via `osslsigncode verify` when the tool is
    available on PATH (full digest/chain verification); falls back to
    structural-only parsing via `cryptography` otherwise
  - Insecure auto-update heuristic: update-related strings/URLs present in
    a binary with no evidence of WinVerifyTrust/CryptQueryObject-style
    signature-verification APIs imported

Platform note: full Authenticode chain-of-trust validation (revocation,
timestamp authority checks) is most reliable via Windows `signtool verify`.
This module runs `osslsigncode verify` when present for a real digest check,
and always performs its own structural cert parsing so the tool works the
same way on any analyst workstation. See README for the exact scope of each
check.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from core.fs_walk import find_pe_files
from core.models import Finding, Severity
from core.pe_utils import (
    extract_pkcs7_from_win_certificate,
    extract_strings_from_bytes,
    get_security_directory_bytes,
    is_pe_file,
    parse_pe,
)

WEAK_HASH_ALGORITHMS = {"sha1", "md5"}

# Import functions whose presence indicates the binary itself does some
# form of signature/trust verification (relevant to the auto-update check).
TRUST_VERIFY_APIS = {
    "winverifytrust", "cryptqueryobject", "cryptmsggetparam",
    "certgetcertificatechain", "certverifycertificatechainpolicy",
    "cryptverifymessagesignature",
}

# Loose signal words for "this binary probably has an update mechanism".
UPDATE_KEYWORDS = ("update", "autoupdate", "updater", "upgrade", "/version", "manifest.json")


@dataclass
class CertSummary:
    subject_cn: str
    issuer_cn: str
    not_valid_before: Optional[datetime]
    not_valid_after: Optional[datetime]
    signature_hash_algorithm: str
    self_signed: bool
    is_expired: bool
    serial_number: str = ""
    is_ca: bool = False


@dataclass
class BinarySignatureInfo:
    path: str
    is_signed: bool
    certs: list[CertSummary] = field(default_factory=list)
    parse_error: Optional[str] = None
    osslsigncode_output: Optional[str] = None
    osslsigncode_verified: Optional[bool] = None  # None = tool unavailable
    osslsigncode_digest_mismatch: bool = False
    timestamp_present: Optional[bool] = None


def _cn_from_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    return name.rfc4514_string()


def _cert_not_valid_before(cert: x509.Certificate) -> datetime:
    # cryptography >=42 exposes tz-aware *_utc accessors; fall back for older versions.
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)


def _cert_not_valid_after(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)


def parse_signature(pe_path: Path) -> BinarySignatureInfo:
    """Extract and structurally parse the Authenticode signature, if present."""
    raw = get_security_directory_bytes(pe_path)
    if raw is None:
        return BinarySignatureInfo(path=str(pe_path), is_signed=False)

    pkcs7_der = extract_pkcs7_from_win_certificate(raw)
    if not pkcs7_der:
        return BinarySignatureInfo(
            path=str(pe_path), is_signed=False,
            parse_error="Security directory present but WIN_CERTIFICATE blob was empty/malformed",
        )

    try:
        with warnings.catch_warnings():
            # Authenticode signatures are commonly BER- not strict-DER-encoded;
            # cryptography's fallback handles this correctly, the warning is benign.
            warnings.filterwarnings("ignore", message="PKCS#7 certificates could not be parsed as DER")
            certs = pkcs7.load_der_pkcs7_certificates(pkcs7_der)
    except Exception as e:
        return BinarySignatureInfo(
            path=str(pe_path), is_signed=True,
            parse_error=f"Failed to parse PKCS#7 certificate blob: {e}",
        )

    now = datetime.now(timezone.utc)
    summaries: list[CertSummary] = []
    for cert in certs:
        subject_cn = _cn_from_name(cert.subject)
        issuer_cn = _cn_from_name(cert.issuer)
        not_before = _cert_not_valid_before(cert)
        not_after = _cert_not_valid_after(cert)
        summaries.append(
            CertSummary(
                subject_cn=subject_cn,
                issuer_cn=issuer_cn,
                not_valid_before=not_before,
                not_valid_after=not_after,
                signature_hash_algorithm=cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
                self_signed=(subject_cn == issuer_cn),
                is_expired=(now > not_after if not_after else False),
                serial_number=hex(cert.serial_number),
                is_ca=_is_ca_certificate(cert),
            )
        )

    return BinarySignatureInfo(path=str(pe_path), is_signed=True, certs=summaries)


def _is_ca_certificate(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bool(bc.ca)
    except Exception:
        return False


def run_osslsigncode_verify(pe_path: Path) -> tuple[Optional[bool], Optional[str], bool]:
    """
    Shell out to `osslsigncode verify` for a real digest/chain check, if the
    tool is available on PATH.

    Returns (verified, raw_output, digest_mismatch):
      - verified is None if the tool isn't installed (caller falls back to
        structural parsing only).
      - digest_mismatch is True only when the file's calculated digest does
        not match the digest recorded in the signature — i.e. real evidence
        of tampering/modification after signing. Chain-of-trust failures
        (self-signed, expired, untrusted root — already surfaced as their
        own structural findings) do NOT set this flag, to avoid double-
        counting the same self-signed cert as both "self-signed" and a
        Critical "verification failed" finding.
    """
    if shutil.which("osslsigncode") is None:
        return None, None, False

    try:
        result = subprocess.run(
            ["osslsigncode", "verify", str(pe_path)],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f"osslsigncode invocation failed: {e}", False

    output = (result.stdout or "") + (result.stderr or "")
    verified = "Signature verification: ok" in output and result.returncode == 0

    digest_mismatch = False
    current_m = re.search(r"Current message digest\s*:\s*([0-9A-Fa-f]+)", output)
    calculated_m = re.search(r"Calculated message digest\s*:\s*([0-9A-Fa-f]+)", output)
    if current_m and calculated_m and current_m.group(1) != calculated_m.group(1):
        digest_mismatch = True
    if "Signature Mismatch" in output or "data has been modified" in output.lower():
        digest_mismatch = True

    return verified, output.strip(), digest_mismatch


def _findings_for_binary(sig_info: BinarySignatureInfo, use_osslsigncode: bool) -> list[Finding]:
    findings: list[Finding] = []
    path = sig_info.path

    if use_osslsigncode:
        verified, output, digest_mismatch = run_osslsigncode_verify(Path(path))
        sig_info.osslsigncode_verified = verified
        sig_info.osslsigncode_output = output
        sig_info.osslsigncode_digest_mismatch = digest_mismatch
        if output:
            lower = output.lower()
            sig_info.timestamp_present = "timestamp" in lower and "no timestamp" not in lower

    if not sig_info.is_signed:
        findings.append(
            Finding(
                module="signature",
                rule_id="unsigned-binary",
                title="Unsigned executable/library",
                severity=Severity.HIGH,
                file_path=path,
                evidence="No Authenticode signature (security directory) present",
                description=(
                    "This binary carries no Authenticode signature, so its "
                    "origin and integrity cannot be cryptographically "
                    "verified. Unsigned binaries are easier to tamper with "
                    "or substitute without detection, and are often flagged "
                    "by endpoint security and SmartScreen."
                ),
                remediation=(
                    "Sign all shipped executables and libraries with a "
                    "valid code-signing certificate from a trusted CA, and "
                    "verify signatures as part of the build/release pipeline."
                ),
                tags=["signature", "integrity"],
                confidence="High",
                poc=(
                    f"1. Confirm no signature is present directly:\n"
                    f"     Windows (PowerShell):\n"
                    f"       Get-AuthenticodeSignature -FilePath \"{path}\" | Format-List\n"
                    f"       (Status will show 'NotSigned')\n"
                    f"     Linux:\n"
                    f"       osslsigncode verify \"{path}\"\n"
                    f"       (Output will show 'No signature found')\n\n"
                    f"2. Impact demonstration: because there is no signature, "
                    f"Windows SmartScreen/AppLocker/WDAC publisher-based rules "
                    f"cannot distinguish this binary from a tampered or malicious "
                    f"replacement. If this file sits in a writable location "
                    f"(cross-reference any writable-directory finding for the same "
                    f"path), an attacker's replacement binary would be "
                    f"indistinguishable from the original at the OS trust level.\n\n"
                    f"3. For the client report: capture the "
                    f"Get-AuthenticodeSignature output as evidence alongside a "
                    f"screenshot of the file's Properties > Digital Signatures tab "
                    f"in Windows Explorer (which will show no 'Digital Signatures' "
                    f"tab at all for an unsigned file)."
                ),
            )
        )
        return findings

    if sig_info.parse_error:
        findings.append(
            Finding(
                module="signature",
                rule_id="signature-parse-error",
                title="Authenticode signature present but could not be parsed",
                severity=Severity.MEDIUM,
                file_path=path,
                evidence=sig_info.parse_error,
                description=(
                    "A signature directory exists but Warden could not "
                    "parse it structurally. This can indicate a malformed or "
                    "non-standard signature blob and warrants manual review "
                    "with `signtool verify` or `osslsigncode verify`."
                ),
                remediation="Manually inspect this binary's signature with signtool or osslsigncode.",
                tags=["signature", "integrity", "gap"],
                confidence="Low",
            )
        )

    if sig_info.certs:
        chain = " -> ".join(f"{c.subject_cn} (issuer: {c.issuer_cn})" for c in sig_info.certs)
        chain_extra = [{
            "subject_cn": c.subject_cn,
            "issuer_cn": c.issuer_cn,
            "not_valid_before": c.not_valid_before.isoformat() if c.not_valid_before else None,
            "not_valid_after": c.not_valid_after.isoformat() if c.not_valid_after else None,
            "signature_hash_algorithm": c.signature_hash_algorithm,
            "self_signed": c.self_signed,
            "is_expired": c.is_expired,
            "serial_number": c.serial_number,
            "is_ca": c.is_ca,
        } for c in sig_info.certs]
        findings.append(Finding(
            module="signature",
            rule_id="certificate-chain-summary",
            title="Certificate chain extracted",
            severity=Severity.INFO,
            file_path=path,
            evidence=chain,
            description="Warden extracted the Authenticode certificate chain for publisher and trust review.",
            remediation="Verify the leaf publisher is expected, the chain terminates at a trusted CA, and the certificate is appropriate for production code signing.",
            tags=["signature", "certificate-chain"],
            confidence="Medium",
            extra={"certificate_chain": chain_extra},
        ))

        leaf = sig_info.certs[0]
        publisher_name = leaf.subject_cn.strip()
        unknown_markers = ("unknown", "test", "localhost", "default", "sample")
        if not publisher_name or any(m in publisher_name.lower() for m in unknown_markers):
            findings.append(Finding(
                module="signature",
                rule_id="unknown-publisher",
                title="Unknown or placeholder publisher detected",
                severity=Severity.MEDIUM,
                file_path=path,
                evidence=publisher_name or "missing publisher common name",
                description="The signing certificate subject does not identify a clear production publisher.",
                remediation="Use a production code-signing certificate with an organization/publisher identity users can recognize and trust.",
                tags=["signature", "publisher", "reputation"],
                confidence="Medium",
            ))
        elif leaf.self_signed or sig_info.osslsigncode_verified is False:
            findings.append(Finding(
                module="signature",
                rule_id="publisher-reputation-review",
                title="Publisher reputation requires review",
                severity=Severity.LOW,
                file_path=path,
                evidence=publisher_name,
                description="The publisher was extracted, but trust verification was incomplete or failed. This is a reputation review signal rather than an external reputation lookup.",
                remediation="Confirm the publisher is expected, trusted by target endpoints, and consistent across released binaries.",
                tags=["signature", "publisher", "reputation"],
                confidence="Low",
            ))

    if sig_info.timestamp_present is False:
        findings.append(Finding(
            module="signature",
            rule_id="missing-signature-timestamp",
            title="Authenticode timestamp not detected",
            severity=Severity.MEDIUM,
            file_path=path,
            evidence="osslsigncode output did not report a timestamp",
            description="A signed binary without a timestamp may stop validating when the signing certificate expires.",
            remediation="Timestamp signatures during release signing using a trusted RFC3161 timestamp authority.",
            tags=["signature", "timestamp"],
            confidence="Medium",
        ))
    elif sig_info.timestamp_present is True:
        findings.append(Finding(
            module="signature",
            rule_id="signature-timestamp-present",
            title="Authenticode timestamp detected",
            severity=Severity.INFO,
            file_path=path,
            evidence="Timestamp information present in signature verification output",
            description="The signature appears to include timestamp information, which helps signatures remain valid after certificate expiry.",
            remediation="Continue timestamping all production code signatures and monitor timestamp authority trust.",
            tags=["signature", "timestamp"],
            confidence="Medium",
        ))

    if sig_info.osslsigncode_verified is False and sig_info.osslsigncode_digest_mismatch:
        findings.append(
            Finding(
                module="signature",
                rule_id="signature-verification-failed",
                title="Authenticode signature failed verification (osslsigncode)",
                severity=Severity.CRITICAL,
                file_path=path,
                evidence=(sig_info.osslsigncode_output or "")[:500],
                description=(
                    "`osslsigncode verify` reported that this binary's "
                    "embedded signature does not validate. This can mean the "
                    "file was modified after signing, the signature is "
                    "corrupt, or the certificate chain does not resolve to a "
                    "trusted root — all of which undermine the integrity "
                    "guarantee the signature is supposed to provide."
                ),
                remediation=(
                    "Re-sign the binary from a clean build, and confirm the "
                    "release pipeline isn't modifying files after the "
                    "signing step (e.g. resource injection, packer, post-"
                    "processing)."
                ),
                tags=["signature", "integrity"],
                confidence="High",
                poc=(
                    f"1. Reproduce the digest mismatch directly:\n"
                    f"     osslsigncode verify \"{path}\"\n"
                    f"   Compare the 'Current message digest' against the "
                    f"'Calculated message digest' in the output — a mismatch means "
                    f"the file's actual content hash no longer matches the hash "
                    f"that was signed.\n\n"
                    f"2. Cross-check on Windows for a second, independent data point:\n"
                    f"     Get-AuthenticodeSignature -FilePath \"{path}\" | Format-List\n"
                    f"   Status will show 'HashMismatch'.\n\n"
                    f"3. If you have an earlier known-good copy of this binary "
                    f"(from the original installer, a prior release, or vendor "
                    f"distribution), diff the two to identify what changed:\n"
                    f"     Windows: fc /b original.exe \"{path}\"\n"
                    f"     Linux:   cmp -l original.exe \"{path}\" | head\n\n"
                    f"4. Document the finding with the full osslsigncode output "
                    f"(see JSON export) as evidence — this is strong evidence of "
                    f"post-signing modification (supply-chain tampering, a packer/"
                    f"resource-editing step after signing, or malicious injection)."
                ),
            )
        )

    for cert in sig_info.certs:
        if cert.is_expired:
            findings.append(
                Finding(
                    module="signature",
                    rule_id="expired-signing-certificate",
                    title=f"Expired code-signing certificate — {cert.subject_cn}",
                    severity=Severity.HIGH,
                    file_path=path,
                    evidence=f"Certificate valid until {cert.not_valid_after}",
                    description=(
                        f"The code-signing certificate for '{cert.subject_cn}' "
                        f"expired on {cert.not_valid_after}. Depending on "
                        f"whether the signature carries a valid RFC3161 "
                        f"timestamp, Windows may or may not still treat this "
                        f"binary as validly signed — either way it signals "
                        f"stale release/signing hygiene."
                    ),
                    remediation="Re-sign with a current certificate and ensure timestamping is used on all signatures.",
                    tags=["signature", "certificate", "expired"],
                    confidence="Medium",
                    poc=(
                        f"1. Confirm the certificate validity period directly:\n"
                        f"     Windows (PowerShell):\n"
                        f"       $sig = Get-AuthenticodeSignature -FilePath \"{path}\"\n"
                        f"       $sig.SignerCertificate | Format-List Subject,NotBefore,NotAfter\n"
                        f"     Linux:\n"
                        f"       osslsigncode verify \"{path}\"   # shows cert validity dates\n\n"
                        f"2. Check whether the signature carries a valid RFC3161 "
                        f"timestamp (a timestamped signature can remain valid after "
                        f"cert expiry; an untimestamped one cannot):\n"
                        f"       osslsigncode verify \"{path}\" | grep -i timestamp\n\n"
                        f"3. If untimestamped and expired, demonstrate the practical "
                        f"impact: on a clean test machine with the system clock set "
                        f"past {cert.not_valid_after}, Windows SmartScreen/AppLocker "
                        f"will treat this binary as unsigned/untrusted, which can "
                        f"break update mechanisms or trigger user-facing security "
                        f"warnings during the engagement window if the client hasn't "
                        f"already re-signed."
                    ),
                )
            )

        if cert.self_signed:
            findings.append(
                Finding(
                    module="signature",
                    rule_id="self-signed-certificate",
                    title=f"Self-signed code-signing certificate — {cert.subject_cn}",
                    severity=Severity.MEDIUM,
                    file_path=path,
                    evidence=f"Subject and issuer both '{cert.subject_cn}'",
                    description=(
                        "This binary is signed with a self-signed certificate "
                        "rather than one issued by a trusted public CA. "
                        "Self-signed certificates provide integrity checking "
                        "but no independent identity verification, and will "
                        "not be trusted by default on end-user machines."
                    ),
                    remediation="Obtain a code-signing certificate from a trusted public CA for production releases.",
                    tags=["signature", "certificate", "self-signed"],
                    confidence="Medium",
                    poc=(
                        f"1. Confirm the self-signed chain directly:\n"
                        f"     osslsigncode verify \"{path}\"\n"
                        f"   Expect a chain-of-trust error (e.g. 'self signed "
                        f"certificate') since Subject and Issuer both resolve to "
                        f"'{cert.subject_cn}'.\n\n"
                        f"2. On Windows, confirm the end-user experience directly: "
                        f"copy the binary to a clean machine that has never had this "
                        f"publisher's cert added to its Trusted Publishers/Root "
                        f"store, then check:\n"
                        f"     Get-AuthenticodeSignature -FilePath \"{path}\" | "
                        f"Select Status, StatusMessage\n"
                        f"   Expect Status = 'UnknownError' or similar, and no green "
                        f"'verified publisher' indication in the file's Properties > "
                        f"Digital Signatures tab.\n\n"
                        f"3. Confirm whether this cert is the client's intentional "
                        f"internal-tooling cert (common and low-risk for internal-"
                        f"only utilities) versus something shipped to end customers "
                        f"(higher-risk, since customers have no basis to trust it)."
                    ),
                )
            )

        if cert.signature_hash_algorithm.lower() in WEAK_HASH_ALGORITHMS:
            findings.append(
                Finding(
                    module="signature",
                    rule_id="weak-signature-algorithm",
                    title=f"Weak signature hash algorithm ({cert.signature_hash_algorithm}) — {cert.subject_cn}",
                    severity=Severity.HIGH,
                    file_path=path,
                    evidence=f"Certificate signed using {cert.signature_hash_algorithm}",
                    description=(
                        f"The certificate for '{cert.subject_cn}' uses "
                        f"{cert.signature_hash_algorithm}, which has known "
                        f"collision weaknesses and is deprecated for code "
                        f"signing. Modern tooling and OS trust policies "
                        f"increasingly reject SHA-1/MD5-signed binaries "
                        f"outright."
                    ),
                    remediation="Re-sign using SHA-256 or stronger.",
                    tags=["signature", "certificate", "weak-crypto"],
                    confidence="High",
                    poc=(
                        f"1. Confirm the signature algorithm directly:\n"
                        f"     openssl asn1parse -in \"{path}\" -inform DER 2>/dev/null | "
                        f"grep -A2 algorithm\n"
                        f"   or, more directly:\n"
                        f"     osslsigncode verify \"{path}\"   # prints signature algorithm\n\n"
                        f"2. Confirm current OS trust policy impact: on Windows 10/11 "
                        f"builds with SHA-1 code-signing deprecation enforced, "
                        f"binaries signed only with SHA-1 (no dual SHA-256 "
                        f"signature) are treated as unsigned by SmartScreen/WDAC. "
                        f"Verify on a current Windows build:\n"
                        f"     Get-AuthenticodeSignature -FilePath \"{path}\" | "
                        f"Select Status, StatusMessage\n\n"
                        f"3. Document both the raw algorithm identifier ({cert.signature_hash_algorithm}) "
                        f"and the observed OS trust outcome as evidence — this "
                        f"combination demonstrates concrete impact rather than a "
                        f"theoretical cryptographic weakness."
                    ),
                )
            )

    return findings


def _publisher_consistency_findings(all_sig_info: list[BinarySignatureInfo]) -> list[Finding]:
    """Cross-binary check: do all signed binaries in this app share a publisher?"""
    publisher_to_files: dict[str, list[str]] = {}
    for info in all_sig_info:
        for cert in info.certs:
            publisher_to_files.setdefault(cert.subject_cn, []).append(info.path)

    if len(publisher_to_files) <= 1:
        return []

    findings: list[Finding] = []
    summary_lines = "; ".join(f"{pub}: {len(files)} file(s)" for pub, files in publisher_to_files.items())
    findings.append(
        Finding(
            module="signature",
            rule_id="mismatched-publisher",
            title="Multiple distinct code-signing publishers within the same application",
            severity=Severity.MEDIUM,
            file_path=", ".join(sorted({f for files in publisher_to_files.values() for f in files})),
            evidence=summary_lines,
            description=(
                "Binaries within this application are signed by more than "
                "one distinct publisher/subject. This can be legitimate "
                "(bundled third-party redistributables) but can also be a "
                "supply-chain inconsistency signal — e.g. a component "
                "replaced or injected after the original release build."
            ),
            remediation=(
                "Confirm each distinct publisher is an expected, legitimate "
                "dependency. Investigate any binary signed by an unexpected "
                "or unfamiliar publisher."
            ),
            tags=["signature", "supply-chain"],
            confidence="Low",
            poc=(
                f"1. List every signed binary and its signer directly:\n"
                f"     Windows (PowerShell), for each file in the app directory:\n"
                f"       Get-ChildItem -Recurse -Include *.exe,*.dll | ForEach-Object "
                f"{{ Get-AuthenticodeSignature $_.FullName }} | "
                f"Select Path, @{{N='Signer';E={{$_.SignerCertificate.Subject}}}}\n\n"
                f"2. Cross-reference the resulting publisher list against: "
                f"{summary_lines}\n\n"
                f"3. For each unexpected publisher, research whether it "
                f"corresponds to a known, legitimate third-party dependency "
                f"(e.g. a bundled runtime, installer framework, or licensed "
                f"component) versus an unexplained addition. Check the file's "
                f"build/modification timestamp against the rest of the release "
                f"to see if it was added out-of-band from the main build.\n\n"
                f"4. If a component with an unfamiliar publisher can't be "
                f"attributed to a known legitimate dependency, treat it as "
                f"requiring escalation and manual deep-dive (static/behavioral "
                f"analysis of that specific binary)."
            ),
        )
    )
    return findings


def _auto_update_finding(pe_path: Path) -> Finding | None:
    """
    Heuristic: does this binary reference update-related URLs/keywords
    without importing any signature/trust-verification API? A real
    positive here means the updater likely trusts downloaded payloads
    without verifying them — a common thick-client finding class.
    """
    try:
        data = pe_path.read_bytes()
    except OSError:
        return None

    strings_with_offsets = extract_strings_from_bytes(data)
    joined_lower = "\n".join(s.lower() for s, _ in strings_with_offsets)

    has_update_signal = any(kw in joined_lower for kw in UPDATE_KEYWORDS)
    if not has_update_signal:
        return None

    pe_info = parse_pe(pe_path)
    if not pe_info.is_valid_pe:
        return None

    all_funcs = {
        fn.lower()
        for funcs in pe_info.imported_functions.values()
        for fn in funcs
    }
    has_trust_api = bool(all_funcs & TRUST_VERIFY_APIS)

    if has_trust_api:
        return None  # looks like it does verify something — no finding

    matched_kw = next(kw for kw in UPDATE_KEYWORDS if kw in joined_lower)
    return Finding(
        module="signature",
        rule_id="insecure-auto-update-indicator",
        title="Possible auto-update mechanism without signature verification",
        severity=Severity.MEDIUM,
        file_path=str(pe_path),
        evidence=f"Update-related string matched ('{matched_kw}'); no WinVerifyTrust/CryptQueryObject-style import found",
        description=(
            "This binary contains strings suggesting an update/version-"
            "check mechanism, but does not import any Windows API commonly "
            "used to verify a downloaded payload's signature before "
            "execution. This is a static heuristic, not proof of an "
            "exploitable auto-update flaw — confirm manually by reviewing "
            "the update flow (ideally with source or a decompiler)."
        ),
        remediation=(
            "Ensure any auto-update mechanism verifies the downloaded "
            "payload's Authenticode signature (e.g. via WinVerifyTrust) "
            "and expected publisher before executing it, and serves "
            "updates over TLS with certificate validation enabled."
        ),
        tags=["signature", "auto-update", "heuristic"],
        confidence="Low",
        poc=(
            f"1. Confirm the update-related string directly:\n"
            f"     strings -n 6 \"{pe_path}\" | grep -i '{matched_kw}'\n"
            f"   (Windows: strings64.exe -n 6 \"{pe_path}\" | findstr /i \"{matched_kw}\")\n\n"
            f"2. Confirm the import table lacks trust-verification APIs:\n"
            f"     dumpbin /imports \"{pe_path}\" | findstr /i \"WinVerifyTrust CryptQueryObject\"\n"
            f"   (expect no output if this finding is accurate)\n\n"
            f"3. Dynamic confirmation (requires a controlled test environment "
            f"and, if the update server is client-owned, written authorization): "
            f"intercept the update check/download with a proxy (Burp/mitmproxy) "
            f"and serve a modified payload with a valid file structure but "
            f"altered content. If the application executes the modified payload "
            f"without rejecting it, this confirms the updater does not verify "
            f"payload integrity/authenticity before execution.\n\n"
            f"4. If dynamic testing is out of scope for this engagement, report "
            f"this as a static indicator requiring source-level or decompiled "
            f"confirmation of the actual update-verification logic before "
            f"treating it as a confirmed (rather than potential) finding."
        ),
    )


def run(
    target_dir: str | Path,
    use_osslsigncode: bool = True,
    single_file: str | Path | None = None,
    progress_callback=None,
    error_callback=None,
) -> list[Finding]:
    """
    Entry point for Module 3. Statically analyzes Authenticode signatures
    across every PE file under target_dir, or — if `single_file` is given —
    just that one PE file.
    """
    target_dir = Path(target_dir)
    single_file = Path(single_file) if single_file else None
    all_findings: list[Finding] = []
    seen_fingerprints: set[str] = set()
    all_sig_info: list[BinarySignatureInfo] = []

    def _add(findings: list[Finding | None]):
        for f in findings:
            if f is None:
                continue
            fp = f.fingerprint()
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                all_findings.append(f)

    for pe_path in find_pe_files(target_dir, single_file=single_file):
        if progress_callback:
            progress_callback(str(pe_path))

        try:
            sig_info = parse_signature(pe_path)
            all_sig_info.append(sig_info)
            _add(_findings_for_binary(sig_info, use_osslsigncode))
            _add([_auto_update_finding(pe_path)])
        except Exception as e:
            if error_callback:
                error_callback(f"signature: skipped '{pe_path}' after error: {e}")
            continue

    # Publisher-consistency cross-checks only make sense across multiple
    # binaries; skip in single-file scope since there's nothing to compare.
    if single_file is None:
        try:
            _add(_publisher_consistency_findings(all_sig_info))
        except Exception as e:
            if error_callback:
                error_callback(f"signature: publisher-consistency check failed: {e}")

    return all_findings
