"""
Java bytecode security checks (static, stdlib only).

Reads a .class file's constant pool (API references + string literals) and
method bodies directly, with no external dependency. A matched reference is
real evidence: the class genuinely calls that API. Works on loose .class
files and on classes inside .jar / .war archives.

Covered:
- Trust-all TLS: an empty X509TrustManager.checkServerTrusted, or a
  HostnameVerifier that returns true (CWE-295).
- Weak cipher: Cipher.getInstance with a DES/RC2/RC4/Blowfish transformation
  or ECB mode (CWE-327).
- Weak hash: MessageDigest.getInstance("MD5"/"MD2"/"SHA-1") (CWE-327).
- Insecure deserialization: ObjectInputStream.readObject (CWE-502).
- Hardcoded database credentials in a JDBC URL (CWE-798).
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from core.models import Finding, Severity

_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
_MAX_CLASS_BYTES = 8 * 1024 * 1024


def _parse(data: bytes):
    """(member refs {'cls.namedesc'}, string literals, methods [(name, desc, code)])."""
    if data[:4] != _CLASS_MAGIC:
        raise ValueError("not a class file")
    cp: list = [None]
    off, count = 8, struct.unpack_from(">H", data, 8)[0]
    off = 10
    i = 1
    while i < count:
        tag = data[off]; off += 1
        if tag == 1:
            ln = struct.unpack_from(">H", data, off)[0]; off += 2
            cp.append(("Utf8", data[off:off + ln].decode("utf-8", "replace"))); off += ln
        elif tag in (3, 4):
            cp.append(("int", None)); off += 4
        elif tag in (5, 6):
            cp.append(("long", None)); off += 8; cp.append(None); i += 1
        elif tag == 7:
            cp.append(("Class", struct.unpack_from(">H", data, off)[0])); off += 2
        elif tag == 8:
            cp.append(("String", struct.unpack_from(">H", data, off)[0])); off += 2
        elif tag in (9, 10, 11):
            cp.append(("Ref", struct.unpack_from(">HH", data, off))); off += 4
        elif tag == 12:
            cp.append(("NT", struct.unpack_from(">HH", data, off))); off += 4
        elif tag == 15:
            cp.append(("MH", None)); off += 3
        elif tag == 16:
            cp.append(("MT", None)); off += 2
        elif tag in (17, 18):
            cp.append(("Dyn", None)); off += 4
        elif tag in (19, 20):
            cp.append(("Mod", None)); off += 2
        else:
            raise ValueError(f"bad constant tag {tag}")
        i += 1

    def utf(idx):
        e = cp[idx] if 0 < idx < len(cp) else None
        return e[1] if e and e[0] == "Utf8" else None

    refs, strings = set(), set()
    for e in cp:
        if not e:
            continue
        if e[0] == "Ref":
            ci, nti = e[1]
            cls = utf(cp[ci][1]) if cp[ci] and cp[ci][0] == "Class" else None
            nt = cp[nti]
            if cls and nt and nt[0] == "NT":
                refs.add(f"{cls}.{utf(nt[1][0])}{utf(nt[1][1])}")
        elif e[0] == "String":
            s = utf(e[1])
            if s:
                strings.add(s)

    return refs, strings, _methods(data, cp, _after_cp(data))


def _after_cp(data: bytes) -> int:
    """Byte offset just past the constant pool (re-walk; cheap)."""
    off, count = 10, struct.unpack_from(">H", data, 8)[0]
    i = 1
    while i < count:
        tag = data[off]; off += 1
        if tag == 1:
            off += 2 + struct.unpack_from(">H", data, off)[0]
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            off += 4
        elif tag in (5, 6):
            off += 8; i += 1
        elif tag in (7, 8, 16, 19, 20):
            off += 2
        elif tag == 15:
            off += 3
        else:
            raise ValueError(f"bad constant tag {tag}")
        i += 1
    return off


def _methods(data: bytes, cp: list, off: int):
    def utf(idx):
        e = cp[idx] if 0 < idx < len(cp) else None
        return e[1] if e and e[0] == "Utf8" else None

    off += 6  # access_flags, this_class, super_class
    ic = struct.unpack_from(">H", data, off)[0]; off += 2 + 2 * ic

    def members():
        nonlocal off
        n = struct.unpack_from(">H", data, off)[0]; off += 2
        out = []
        for _ in range(n):
            _acc, ni, di = struct.unpack_from(">HHH", data, off); off += 6
            ac = struct.unpack_from(">H", data, off)[0]; off += 2
            code = None
            for _ in range(ac):
                an, al = struct.unpack_from(">HI", data, off); off += 6
                if utf(an) == "Code" and al >= 8:
                    clen = struct.unpack_from(">I", data, off + 4)[0]
                    code = data[off + 8:off + 8 + clen]
                off += al
            out.append((utf(ni), utf(di), code))
        return out

    members()          # fields
    return members()   # methods


_WEAK_CIPHERS = {
    "DES": (Severity.MEDIUM, "DES (56-bit, brute-forceable)"),
    "DESEDE": (Severity.LOW, "Triple DES (64-bit block, Sweet32; deprecated)"),
    "TRIPLEDES": (Severity.LOW, "Triple DES (deprecated)"),
    "RC4": (Severity.MEDIUM, "RC4 (broken stream cipher)"),
    "ARCFOUR": (Severity.MEDIUM, "RC4/ARCFOUR (broken stream cipher)"),
    "RC2": (Severity.MEDIUM, "RC2 (broken legacy cipher)"),
    "BLOWFISH": (Severity.LOW, "Blowfish (64-bit block, legacy)"),
}
_WEAK_HASHES = {
    "MD5": (Severity.MEDIUM, "MD5 (collision-broken)"),
    "MD2": (Severity.MEDIUM, "MD2 (broken)"),
    "SHA-1": (Severity.LOW, "SHA-1 (collision-weak)"),
    "SHA1": (Severity.LOW, "SHA-1 (collision-weak)"),
}
_TRUSTMANAGER_DESC = "Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"
_HOSTNAME_DESC_SUFFIX = "Ljavax/net/ssl/SSLSession;)Z"


def _f(rule, title, sev, label, evidence, desc, rem, cwe, conf="High") -> Finding:
    return Finding(
        module="re_exposure", rule_id=rule, title=title, severity=sev, file_path=label,
        evidence=evidence, description=desc, remediation=rem,
        tags=["java", "managed-code", cwe.lower()], confidence=conf,
        poc=("1. Confirm in the class with a Java decompiler (CFR, procyon, JD-GUI):\n"
             f"     cfr '{label.split(' > ')[0]}'\n"
             f"2. Evidence: {evidence}"))


def _returns_true(code: bytes | None) -> bool:
    if not code:
        return False
    body = bytes(b for b in code if b != 0x00)
    return body == b"\x04\xac"          # iconst_1 ; ireturn


def _is_empty_void(code: bytes | None) -> bool:
    if code is None:
        return False
    body = bytes(b for b in code if b != 0x00)
    return body in (b"", b"\xb1")        # <empty> / return


def check_class(data: bytes, label: str) -> list[Finding]:
    """Findings for one .class file. [] if not a parseable class."""
    try:
        refs, strings, methods = _parse(data)
    except Exception:
        return []
    findings: list[Finding] = []

    # Weak cipher (only when Cipher.getInstance is actually called).
    if any(r.startswith("javax/crypto/Cipher.getInstance") for r in refs):
        for s in strings:
            parts = [p.strip().upper() for p in s.split("/")]
            algo = parts[0] if parts else ""
            mode = parts[1] if len(parts) > 1 else ""
            if algo in _WEAK_CIPHERS:
                sev, why = _WEAK_CIPHERS[algo]
                findings.append(_f("java-weak-cipher", f"Weak cipher in use: {why}", sev, label,
                                   f"Cipher.getInstance(\"{s}\")",
                                   f"The code encrypts with {why}. Data protected this way is not confidential.",
                                   "Use AES with an authenticated mode (AES/GCM/NoPadding).", "CWE-327"))
                break
            if mode == "ECB" and algo not in ("", "RSA") and 1 < len(parts):
                findings.append(_f("java-ecb-mode", "Insecure cipher mode: ECB", Severity.MEDIUM, label,
                                   f"Cipher.getInstance(\"{s}\")",
                                   "ECB encrypts identical plaintext blocks to identical ciphertext, leaking structure.",
                                   "Use an authenticated mode such as AES/GCM/NoPadding.", "CWE-327"))
                break

    # Weak hash.
    if any(r.startswith("java/security/MessageDigest.getInstance") for r in refs):
        for s in strings:
            key = s.strip().upper()
            if key in _WEAK_HASHES:
                sev, why = _WEAK_HASHES[key]
                findings.append(_f("java-weak-hash", f"Weak hash algorithm: {why}", sev, label,
                                   f"MessageDigest.getInstance(\"{s}\")",
                                   f"{why} must not be used for signatures, integrity or password hashing.",
                                   "Use SHA-256+; for passwords use PBKDF2/bcrypt/Argon2.", "CWE-327"))
                break

    # Insecure deserialization.
    if any(r.startswith("java/io/ObjectInputStream.readObject") for r in refs):
        findings.append(_f("java-insecure-deserialization", "Java deserialization of objects (ObjectInputStream.readObject)",
                           Severity.MEDIUM, label, "Calls java.io.ObjectInputStream.readObject",
                           "Java native deserialization reconstructs arbitrary object graphs. If the stream can come "
                           "from an untrusted source, a gadget chain (ysoserial) yields remote code execution.",
                           "Avoid native serialization for untrusted data; use JSON with a schema, or set a strict "
                           "ObjectInputFilter (JEP 290) allow-list.", "CWE-502", conf="Medium"))

    # Hardcoded DB credentials in a JDBC URL.
    for s in strings:
        low = s.lower()
        if low.startswith("jdbc:") and ("password=" in low or "pwd=" in low):
            findings.append(_f("java-hardcoded-db-credentials", "Hardcoded database credentials in JDBC URL",
                               Severity.HIGH, label, s,
                               "A JDBC connection string with an embedded password is compiled into the class. Anyone "
                               "with the .jar can read it and reach the database.",
                               "Move credentials to a secrets manager or external config; never embed them in code.",
                               "CWE-798"))
            break

    # Trust-all TLS (method bodies).
    for name, desc, code in methods:
        if name == "checkServerTrusted" and desc and desc.endswith(_TRUSTMANAGER_DESC) and _is_empty_void(code):
            findings.append(_f("java-tls-trustmanager-trust-all", "TLS certificate validation disabled (empty X509TrustManager)",
                               Severity.HIGH, label, "checkServerTrusted has an empty body (accepts any certificate)",
                               "An X509TrustManager whose checkServerTrusted does nothing accepts every certificate, "
                               "including an attacker's. All TLS traffic can be intercepted and modified.",
                               "Remove the custom trust manager and use the platform default, or validate the chain and "
                               "pin the expected certificate.", "CWE-295"))
            break
    for name, desc, code in methods:
        if desc and desc.endswith(_HOSTNAME_DESC_SUFFIX) and _returns_true(code):
            findings.append(_f("java-tls-hostname-verifier-disabled", "TLS hostname verification disabled (verifier returns true)",
                               Severity.HIGH, label, "A HostnameVerifier unconditionally returns true",
                               "A HostnameVerifier that always returns true accepts a certificate for any hostname, so a "
                               "man-in-the-middle with any valid certificate can impersonate the server.",
                               "Do not override hostname verification; if you must, compare against the expected host.",
                               "CWE-295"))
            break
    return findings


def _iter_jar_classes(path: Path):
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".class") and info.file_size <= _MAX_CLASS_BYTES:
                    try:
                        yield info.filename, zf.read(info)
                    except Exception:
                        continue
    except (zipfile.BadZipFile, OSError):
        return


def scan_tree(root: Path, single_file: Path | None = None) -> list[Finding]:
    """Findings for every .class and .jar/.war under root (or a single file)."""
    findings: list[Finding] = []
    if single_file is not None:
        targets = [single_file] if single_file.suffix.lower() in (".jar", ".war", ".class") else []
    else:
        targets = [p for p in root.rglob("*") if p.suffix.lower() in (".jar", ".war", ".class")]
    for p in targets:
        suffix = p.suffix.lower()
        if suffix == ".class":
            try:
                if p.stat().st_size <= _MAX_CLASS_BYTES:
                    findings.extend(check_class(p.read_bytes(), p.name))
            except OSError:
                continue
        else:  # .jar / .war
            for entry, data in _iter_jar_classes(p):
                findings.extend(check_class(data, f"{p.name} > {entry}"))
    return findings
