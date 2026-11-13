"""
.NET assembly checks (static, metadata + lightweight IL).

Unlike the string-based re_exposure checks, these read the assembly's own
metadata tables (via dnfile) and, for two cases that the tables cannot settle,
a few bytes of method-body IL. A matched API *reference* is real evidence: the
assembly genuinely calls that method, with far fewer false positives than a
string match.

Covered:
- Insecure deserialization: BinaryFormatter / SoapFormatter / LosFormatter /
  ObjectStateFormatter / NetDataContractSerializer, and JavaScriptSerializer
  with a type resolver (CWE-502).
- Legacy .NET Remoting server channels with TypeFilterLevel.Full (CWE-502).
- Weak cryptography: DES / RC2 / TripleDES / MD5 / RIPEMD (CWE-327).
- TLS certificate validation disabled: a RemoteCertificateValidationCallback
  wired to a method whose whole body is "return true" (CWE-295).
- Weak TLS protocol pinned: ServicePointManager.SecurityProtocol set to
  Ssl3 / Tls1.0 / Tls1.1 (CWE-327).

If dnfile is unavailable the module degrades to nothing (never a hard error),
exactly like the optional YARA support.
"""
from __future__ import annotations

import logging
from pathlib import Path

from core.models import Finding, Severity

try:
    import dnfile  # type: ignore
    _HAVE_DNFILE = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_DNFILE = False

logger = logging.getLogger("dotnet_checks")

# Reference "Namespace.Type::Method" (or "Namespace.Type::" for any member) ->
# (rule_id, title, severity, consequence, remediation, cwe)
_DANGEROUS_REFS: dict[str, tuple] = {
    "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize": (
        "dotnet-insecure-deserialization", "Insecure deserialization via BinaryFormatter.Deserialize",
        Severity.HIGH,
        "BinaryFormatter.Deserialize reconstructs arbitrary .NET types from the input stream. If any of that data "
        "crosses a trust boundary (a file, a network message, IPC), a crafted payload (ysoserial.net) yields remote "
        "code execution. BinaryFormatter is obsolete and removed in .NET 9.",
        "Replace BinaryFormatter with a contract-based serializer (System.Text.Json, DataContractJsonSerializer, "
        "protobuf). If it cannot be removed, never deserialize data from an untrusted source.",
        "CWE-502"),
    "System.Runtime.Remoting.Metadata.W3cXsd2001.SoapFormatter::Deserialize": (
        "dotnet-insecure-deserialization", "Insecure deserialization via SoapFormatter", Severity.HIGH,
        "SoapFormatter deserializes arbitrary types and is a known RCE gadget sink.",
        "Use a contract-based serializer and never deserialize untrusted input.", "CWE-502"),
    "System.Runtime.Serialization.NetDataContractSerializer::": (
        "dotnet-insecure-deserialization", "Insecure deserialization via NetDataContractSerializer", Severity.HIGH,
        "NetDataContractSerializer embeds and honours .NET type names from the payload, so untrusted input can "
        "instantiate arbitrary gadget types (RCE).",
        "Use DataContractSerializer with a fixed known-types list, or System.Text.Json.", "CWE-502"),
    "System.Web.UI.LosFormatter::": (
        "dotnet-insecure-deserialization", "Insecure deserialization via LosFormatter", Severity.HIGH,
        "LosFormatter (ViewState) deserializes arbitrary types; without a validated MAC it is an RCE sink.",
        "Do not deserialize untrusted LosFormatter data; keep ViewState MAC enabled.", "CWE-502"),
    "System.Web.UI.ObjectStateFormatter::": (
        "dotnet-insecure-deserialization", "Insecure deserialization via ObjectStateFormatter", Severity.HIGH,
        "ObjectStateFormatter deserializes arbitrary types and is a documented RCE gadget sink.",
        "Do not deserialize untrusted input with ObjectStateFormatter.", "CWE-502"),
    "System.Security.Cryptography.DESCryptoServiceProvider::": (
        "dotnet-weak-crypto", "Weak cipher: DES (56-bit) in use", Severity.MEDIUM,
        "DES has a 56-bit key and is brute-forceable in hours. Data encrypted with it is not confidential.",
        "Use AES (Aes.Create) with an authenticated mode (GCM) or CBC + HMAC.", "CWE-327"),
    "System.Security.Cryptography.RC2CryptoServiceProvider::": (
        "dotnet-weak-crypto", "Weak cipher: RC2 in use", Severity.MEDIUM,
        "RC2 is a broken legacy block cipher.", "Use AES.", "CWE-327"),
    "System.Security.Cryptography.TripleDESCryptoServiceProvider::": (
        "dotnet-weak-crypto", "Weak cipher: Triple DES in use", Severity.LOW,
        "3DES provides only 112-bit security, has 64-bit blocks (Sweet32), and is deprecated by NIST.",
        "Migrate to AES.", "CWE-327"),
    "System.Security.Cryptography.MD5CryptoServiceProvider::": (
        "dotnet-weak-hash", "Weak hash: MD5 in use", Severity.MEDIUM,
        "MD5 is collision-broken and must not be used for signatures, integrity or password hashing.",
        "Use SHA-256+; for passwords use PBKDF2/bcrypt/Argon2 (Rfc2898DeriveBytes).", "CWE-327"),
    "System.Security.Cryptography.RIPEMD160Managed::": (
        "dotnet-weak-hash", "Weak hash: RIPEMD-160 in use", Severity.LOW,
        "RIPEMD-160 is a legacy hash with a short digest.", "Use SHA-256 or SHA-3.", "CWE-327"),
}

# JavaScriptSerializer is only dangerous with a type resolver; needs both refs.
_JSS_SER = "System.Web.Script.Serialization.JavaScriptSerializer::"
_JSS_RESOLVERS = (
    "System.Web.Script.Serialization.SimpleTypeResolver::",
    "System.Web.Script.Serialization.JavaScriptTypeResolver::",
)
_REMOTING_SERVER = (
    "System.Runtime.Remoting.Channels.Tcp.TcpServerChannel::",
    "System.Runtime.Remoting.Channels.Http.HttpServerChannel::",
    "System.Runtime.Remoting.Channels.Ipc.IpcServerChannel::",
)
_CERT_CALLBACK_CTOR = "System.Net.Security.RemoteCertificateValidationCallback::.ctor"
_SET_SECURITY_PROTOCOL = "System.Net.ServicePointManager::set_SecurityProtocol"
# SecurityProtocolType enum values considered weak when pinned explicitly.
_WEAK_PROTOCOLS = {48: "Ssl3", 192: "Tls (1.0)", 768: "Tls11 (1.1)"}


def _ref_key(md_class, name: str) -> str | None:
    # dnfile returns HeapItemString, not str — stringify before use.
    tn = getattr(md_class, "TypeName", None)
    if tn is None:
        return None
    tn = str(tn)
    if not tn:
        return None
    ns = str(getattr(md_class, "TypeNamespace", "") or "")
    return f"{ns + '.' if ns else ''}{tn}::{name}"


def _collect_refs(md) -> set[str]:
    """{'Namespace.Type::Method'} for every external member the assembly calls."""
    refs: set[str] = set()
    for r in md.MemberRef or []:
        try:
            key = _ref_key(r.Class.row, str(r.Name))
        except Exception:
            continue
        if key:
            refs.add(key)
            refs.add(key.rsplit("::", 1)[0] + "::")  # type-level, any member
    return refs


def _il_body(data: bytes, rva: int) -> bytes | None:
    """Raw IL of a method from the memory-mapped image (rva == offset)."""
    if not rva or rva + 1 > len(data):
        return None
    b0 = data[rva]
    if (b0 & 0x3) == 0x2:                       # tiny header
        size = b0 >> 2
        return data[rva + 1:rva + 1 + size]
    if (b0 & 0x3) == 0x3:                        # fat header (12 bytes)
        size = int.from_bytes(data[rva + 4:rva + 8], "little")
        return data[rva + 12:rva + 12 + size]
    return None


def _is_return_true(il: bytes) -> bool:
    """Whole body unconditionally returns true, in release or debug form.
    release: ldc.i4.1 ret            (17 2a)
    debug:   ldc.i4.1 stloc.0 br.s 0 ldloc.0 ret  (17 0a 2b 00 06 2a)"""
    body = bytes(b for b in il if b != 0x00)      # strip nop padding
    return body in (b"\x17\x2a", b"\x17\x0a\x2b\x06\x2a")


def _always_true_tokens(data: bytes, md) -> set[int]:
    """MethodDef tokens (0x06......) whose body unconditionally returns true."""
    out: set[int] = set()
    for i, m in enumerate(md.MethodDef or [], start=1):
        il = _il_body(data, m.Rva)
        if il is not None and _is_return_true(il):
            out.add(0x06000000 | i)
    return out


def _trust_all_wired(data: bytes, md, cert_ctor_token: bytes) -> bool:
    """True iff an always-true method is turned into a delegate and passed to
    `newobj RemoteCertificateValidationCallback` — the real trust-all wiring.
    Requiring the newobj excludes unrelated `=> true` property getters."""
    true_tokens = _always_true_tokens(data, md)
    if not true_tokens:
        return False
    newobj = b"\x73" + cert_ctor_token            # newobj <cert callback ctor>
    for m in md.MethodDef or []:
        il = _il_body(data, m.Rva)
        if not il:
            continue
        pos = il.find(newobj)
        while pos != -1:
            window = il[max(0, pos - 24):pos]     # ldftn precedes newobj closely
            for tok in true_tokens:
                if b"\xfe\x06" + tok.to_bytes(4, "little") in window:
                    return True
            pos = il.find(newobj, pos + 1)
    return False


_LDC_SINGLE = {0x16: 0, 0x17: 1, 0x18: 2, 0x19: 3, 0x1a: 4, 0x1b: 5, 0x1c: 6, 0x1d: 7, 0x1e: 8, 0x15: -1}


def _protocol_before_call(il: bytes, call_token: bytes) -> int | None:
    """Value of the int constant pushed immediately before `call <call_token>`.
    The C# compiler folds `set_SecurityProtocol = <enum>` to ldc then call."""
    needle = b"\x28" + call_token               # call <token>
    pos = il.find(needle)
    while pos != -1:
        if pos >= 5 and il[pos - 5] == 0x20:      # ldc.i4 <int32>
            return int.from_bytes(il[pos - 4:pos], "little")
        if pos >= 2 and il[pos - 2] == 0x1f:      # ldc.i4.s <int8>
            return il[pos - 1]
        if pos >= 1 and il[pos - 1] in _LDC_SINGLE:
            return _LDC_SINGLE[il[pos - 1]]
        pos = il.find(needle, pos + 1)
    return None


def _memberref_token(md, type_method: str) -> bytes | None:
    """4-byte metadata token (little-endian) of a MemberRef, by 'Type::Method'."""
    for i, r in enumerate(md.MemberRef or [], start=1):
        try:
            if _ref_key(r.Class.row, str(r.Name)) == type_method:
                return (0x0A000000 | i).to_bytes(4, "little")
        except Exception:
            continue
    return None


def _finding(rule, title, severity, path, evidence, description, remediation, cwe, confidence="High") -> Finding:
    return Finding(
        module="re_exposure", rule_id=rule, title=title, severity=severity, file_path=str(path),
        evidence=evidence, description=description, remediation=remediation,
        tags=["dotnet", "managed-code", cwe.lower()], confidence=confidence,
        poc=("1. Confirm the reference in the assembly metadata:\n"
             f"     python -c \"import dnfile; pe=dnfile.dnPE(r'{path}'); "
             "print([str(m.Name) for m in pe.net.mdtables.MemberRef])\"\n"
             "2. Decompile the method in dnSpyEx / ILSpy and confirm the call reaches untrusted input.\n"
             f"   Evidence: {evidence}"),
    )


def check_assembly(path: Path) -> list[Finding]:
    """Findings for one managed assembly. [] for native PEs or parse failures."""
    if not _HAVE_DNFILE:
        return []
    try:
        pe = dnfile.dnPE(str(path))  # default load parses the CLR metadata
    except Exception:
        return []
    try:
        if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
            return []
        md = pe.net.mdtables
        refs = _collect_refs(md)
        findings: list[Finding] = []
        seen_rules: set[str] = set()

        for ref, (rule, title, sev, desc, rem, cwe) in _DANGEROUS_REFS.items():
            key = ref if ref.endswith("::") else ref
            hit = ref in refs or (ref.endswith("::") and ref in refs)
            if hit and (rule, title) not in seen_rules:
                seen_rules.add((rule, title))
                findings.append(_finding(rule, title, sev, path, f"Assembly references {ref.rstrip(':')}", desc, rem, cwe))

        if _JSS_SER in refs and any(r in refs for r in _JSS_RESOLVERS):
            findings.append(_finding(
                "dotnet-insecure-deserialization", "Insecure deserialization via JavaScriptSerializer type resolver",
                Severity.HIGH, path, "References JavaScriptSerializer with a JavaScriptTypeResolver/SimpleTypeResolver",
                "JavaScriptSerializer with a type resolver instantiates .NET types named in the JSON, so untrusted "
                "JSON can build arbitrary gadget types (RCE).",
                "Deserialize without a type resolver, or use System.Text.Json with no polymorphic type handling.", "CWE-502"))

        remoting = [r for r in _REMOTING_SERVER if r in refs]
        if remoting:
            findings.append(_finding(
                "dotnet-remoting-server", "Legacy .NET Remoting server channel exposed", Severity.HIGH, path,
                "References " + ", ".join(r.rstrip(":") for r in remoting),
                ".NET Remoting server channels deserialize caller-supplied objects; with TypeFilterLevel.Full (the "
                "setting required for many real uses) this is a well-known unauthenticated RCE surface.",
                "Replace .NET Remoting with a modern, authenticated RPC (gRPC, WCF with message security, REST). If it "
                "must stay, keep TypeFilterLevel at Low and bind only to localhost.", "CWE-502"))

        # IL-dependent checks.
        data = pe.get_memory_mapped_image()
        cert_ctor = _memberref_token(md, _CERT_CALLBACK_CTOR)
        if cert_ctor is not None:
            # Trust-all = an always-true method wired via ldftn into the
            # RemoteCertificateValidationCallback newobj (not just any delegate).
            if _trust_all_wired(data, md, cert_ctor):
                findings.append(_finding(
                    "dotnet-tls-validation-disabled", "TLS certificate validation disabled (callback always returns true)",
                    Severity.HIGH, path, "RemoteCertificateValidationCallback wired to a method whose body is 'return true'",
                    "A server-certificate validation callback that unconditionally returns true accepts any certificate, "
                    "including an attacker's. All HTTPS traffic from this app can be intercepted and modified.",
                    "Remove the override and let the platform validate, or validate errors == SslPolicyErrors.None and "
                    "pin the expected certificate/key.", "CWE-295"))
            else:
                findings.append(_finding(
                    "dotnet-custom-cert-validation", "Custom TLS certificate validation present — review",
                    Severity.LOW, path, "Registers a RemoteCertificateValidationCallback",
                    "The app installs its own server-certificate validation callback. This is only safe if it rejects "
                    "policy errors; a callback that ignores them silently disables TLS authentication.",
                    "Confirm the callback returns false on any SslPolicyErrors, and pins the expected certificate if used.",
                    "CWE-295", confidence="Low"))

        token = _memberref_token(md, _SET_SECURITY_PROTOCOL)
        if token:
            for m in md.MethodDef or []:
                il = _il_body(data, m.Rva)
                if not il:
                    continue
                val = _protocol_before_call(il, token)
                if val in _WEAK_PROTOCOLS:
                    findings.append(_finding(
                        "dotnet-weak-tls-protocol", f"Weak TLS protocol pinned: {_WEAK_PROTOCOLS[val]}", Severity.MEDIUM,
                        path, f"ServicePointManager.SecurityProtocol set to {_WEAK_PROTOCOLS[val]} (enum value {val})",
                        f"The app forces {_WEAK_PROTOCOLS[val]}, a protocol with known cryptographic weaknesses "
                        "(POODLE, BEAST). It also prevents negotiating TLS 1.2/1.3.",
                        "Leave SecurityProtocol at SystemDefault, or set it to Tls12 | Tls13.", "CWE-327"))
                    break
        return findings
    finally:
        try:
            pe.close()
        except Exception:
            pass
