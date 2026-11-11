"""Default proof-of-concept steps for findings whose module didn't write one.

Every finding a tester sees must show *where* the evidence is, *what* it is
(in full, not a 10-item preview) and *how* to reproduce it independently.
"""
from __future__ import annotations

import json

from core.models import Finding

_PEFILE = 'python -c "import pefile; pe=pefile.PE(r\'{path}\'); {code}"'

# Independent verification commands per rule ({path} = the affected file).
_COMMANDS: dict[str, list[str]] = {
    "aslr-high-entropy-va-disabled": [
        'dumpbin /headers "{path}" | findstr /i "High Entropy Virtual"',
        _PEFILE.format(path="{path}", code="print(hex(pe.OPTIONAL_HEADER.DllCharacteristics), bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x20))"),
    ],
    "safeseh-disabled": [
        'dumpbin /loadconfig "{path}" | findstr /i "SEH"',
        "Get-PESecurity -File \"{path}\"   (SafeSEH column)",
    ],
    "cfg-disabled": [
        'dumpbin /headers "{path}" | findstr /i "Guard"',
        _PEFILE.format(path="{path}", code="print(bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000))"),
    ],
    "high-entropy-section": [
        _PEFILE.format(path="{path}", code="[print(s.Name.decode(errors='ignore').strip(chr(0)), round(s.get_entropy(), 3)) for s in pe.sections]"),
        "Detect It Easy: open the file and check the Entropy / packer view",
    ],
    "known-packer-section-signature": [
        _PEFILE.format(path="{path}", code="[print(s.Name.decode(errors='ignore').strip(chr(0))) for s in pe.sections]"),
        "Detect It Easy: open the file to identify the packer/protector",
    ],
    "certificate-chain-summary": [
        'Get-AuthenticodeSignature -FilePath "{path}" | Format-List *',
        'signtool verify /pa /v "{path}"',
    ],
    "signature-timestamp-present": ['signtool verify /pa /v "{path}"   (look for "The signature is timestamped")'],
    "missing-signature-timestamp": ['signtool verify /pa /v "{path}"   (look for "File is not timestamped")'],
    "signature-digest-not-verified": ['signtool verify /pa /v "{path}"', 'osslsigncode verify "{path}"'],
    "unknown-publisher": ['Get-AuthenticodeSignature -FilePath "{path}" | Select -Expand SignerCertificate | Format-List Subject,Issuer'],
    "publisher-reputation-review": ['Get-AuthenticodeSignature -FilePath "{path}" | Format-List Status,StatusMessage,SignerCertificate'],
    "manifest-privilege-settings": ['mt.exe -inputresource:"{path};#1" -out:manifest.xml', "Resource Hacker / CFF Explorer: open the RT_MANIFEST resource"],
    "embedded-manifest-present": ['mt.exe -inputresource:"{path};#1" -out:manifest.xml'],
    "binary-dependency-graph": ['dumpbin /dependents "{path}"'],
    "no-anti-debug-apis-detected": ['dumpbin /imports "{path}" | findstr /i "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess"'],
    "crypto-usage-detected": ['strings64.exe -n 6 "{path}" | findstr /i "aes rsa rc4 md5 sha1 bcrypt pbkdf2"'],
    "compiler-framework-detected": ['dumpbin /imports "{path}"', "Detect It Easy: open the file to confirm the compiler/runtime"],
    "acl-check-limited": ['icacls "{path}"'],
    "config-intelligence-setting": ['Select-String -Path "{path}" -SimpleMatch -Pattern "{key}"', "grep -nF -- '{key}' \"{path}\""],
}
for _kind in ("urls", "ips", "domains", "registry-keys", "guids", "named-pipes", "mutexs"):
    _COMMANDS[f"extracted-{_kind}"] = ['strings64.exe -n 6 "{path}" | findstr /i "{first_item}"']
_COMMANDS["interesting-strings"] = ['strings64.exe -n 6 "{path}" | findstr /i "{first_item}"']

# extra[...] keys that hold the complete item list behind a summarized evidence string.
_LIST_KEYS = ("url", "ip", "domain", "registry-key", "guid", "named-pipe", "mutex", "strings",
              "crypto", "frameworks", "files", "publishers")


def _indent(text: str) -> str:
    return "\n".join("     " + line for line in str(text).splitlines() or [""])


def default_poc(f: Finding) -> str:
    location = f.file_path or "(scan target)"
    if f.offset is not None:
        location += f" (file offset 0x{f.offset:X})"
    elif f.line_number:
        location += f" (line {f.line_number})"

    items: list[str] = []
    for key in _LIST_KEYS:
        value = f.extra.get(key)
        if isinstance(value, list):
            items.extend(str(v) for v in value)
        elif isinstance(value, dict):
            items.extend(f"{k}: {v}" for k, v in value.items())

    config = f.extra.get("config") or {}
    fmt = {"path": f.file_path, "first_item": (items[0] if items else f.evidence)[:60].replace('"', ""),
           "key": str(config.get("key", "")).split(".")[-1]}
    commands = [c.format(**fmt) for c in _COMMANDS.get(f.rule_id, [])]

    steps = [f"1. Location: {location}"]
    if commands:
        steps.append("2. Reproduce independently:\n" + "\n".join(_indent(c) for c in commands))
    else:
        steps.append("2. Open the file at the location above and confirm the evidence below is present.")
    if items:  # one per line — the evidence string is the same list comma-joined
        evidence_block = f"3. Evidence ({len(items)} item(s)):\n" + "\n".join(_indent(i) for i in items)
    else:
        evidence_block = f"3. Evidence:\n{_indent(f.evidence)}"
    if f.extra.get("context"):
        evidence_block += f"\n   Context:\n{_indent(f.extra['context'])}"
    if f.extra.get("manifest"):
        evidence_block += f"\n   Embedded manifest:\n{_indent(f.extra['manifest'])}"
    if f.extra.get("certificate_chain"):
        evidence_block += "\n   Certificate chain:\n" + _indent(json.dumps(f.extra["certificate_chain"], indent=2, default=str))
    steps.append(evidence_block)
    return "\n\n".join(steps)


def fill_missing_pocs(findings: list[Finding]) -> None:
    for f in findings:
        if not (f.poc or "").strip():
            f.poc = default_poc(f)
