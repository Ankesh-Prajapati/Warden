"""Regression checks for the review fixes. Run: python -m pytest tests  (or: python tests/test_fixes.py)"""
from __future__ import annotations

import json
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import archive_extractor  # noqa: E402
from core.dll_hijack_module import (  # noqa: E402
    _is_unquoted_vulnerable,
    parse_services_from_reg_text,
    parse_services_from_sc_query_text,
)
from core.models import Finding, Severity  # noqa: E402
from core.scanner import ScanCancelled, run_scan  # noqa: E402

SECRET_FILES = {
    "app.config": 'aws_key = AKIAIOSFODNN7ABCDEFG\npassword = "S3cr3t!Pass2024xyz"\n',
    "app.yaml": "debug_since: 2024-01-01\napi_token: abc123XYZ987secretvalue\n",
    "db.ini": "[db]\npassword = P%ssw0rd!Real\nhost = 10.0.0.5\n",
}


def _target(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="warden_test_"))
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_fingerprint_distinguishes_evidence():
    a = Finding("dll_hijack", "phantom-dll-import", "t", Severity.INFO, "x.exe", "Imports 'a.dll'")
    b = Finding("dll_hijack", "phantom-dll-import", "t", Severity.INFO, "x.exe", "Imports 'b.dll'")
    assert a.fingerprint() != b.fingerprint()
    assert Finding.from_dict(a.to_dict()).fingerprint() == a.fingerprint()


def test_sc_query_quoted_path_not_flagged():
    text = (
        'SERVICE_NAME: Good\nBINARY_PATH_NAME : "C:\\Program Files\\App\\svc.exe" -k x\n'
        "SERVICE_NAME: Bad\nBINARY_PATH_NAME : C:\\Program Files\\Vuln App\\svc.exe\n"
    )
    verdicts = {e.name: _is_unquoted_vulnerable(e.image_path) for e in parse_services_from_sc_query_text(text, "s")}
    assert verdicts == {"Good": False, "Bad": True}


def test_reg_hex2_and_escaped_imagepath():
    path = "C:\\Program Files\\Vuln App\\svc.exe"
    hexv = ",".join(f"{b:02x}" for b in path.encode("utf-16-le") + b"\x00\x00")
    cut = hexv.index(",", 40)
    text = (
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Bad]\r\n"
        f'"ImagePath"=hex(2):{hexv[:cut]},\\\r\n  {hexv[cut + 1:]}\r\n'
        "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Good]\r\n"
        '"ImagePath"="\\"C:\\\\Program Files\\\\App\\\\svc.exe\\" -k"\r\n'
    )
    entries = {e.name: e.image_path for e in parse_services_from_reg_text(text, "x.reg")}
    assert entries["Bad"] == path and _is_unquoted_vulnerable(entries["Bad"])
    assert entries["Good"].startswith('"') and not _is_unquoted_vulnerable(entries["Good"])


def test_config_parsing_and_json_export():
    from core.config_intel import extract_interesting_settings
    target = _target(SECRET_FILES)
    keys = {s["key"] for s in extract_interesting_settings(target / "db.ini")}
    assert "db.password" in keys  # a literal % must not drop the whole file
    result = run_scan(target, modules=["secrets"], extract_archives=False)
    json.dumps(result.to_dict(), default=str)  # YAML date must not break export


def test_config_intel_reports_values_not_key_names():
    target = _target({
        "policy.yaml": "password_min_length: 12\ntoken_lifetime: 15\npassword: ${DB_PASSWORD}\napi_key: changeme\n",
        "risky.yaml": "debug: true\nssl_verify: false\nservice_secret: Qp8$wLz2!mRt\n",
    })
    result = run_scan(target, modules=["secrets"], extract_archives=False)
    cfg = [f for f in result.findings if f.rule_id == "config-intelligence-setting"]
    assert not [f for f in cfg if f.file_path.endswith("policy.yaml")], [f.evidence for f in cfg]
    assert {f.extra["config"]["key"] for f in cfg if f.file_path.endswith("risky.yaml")} == {"debug", "ssl_verify", "service_secret"}


def test_extensionless_secret_files_and_sqlite_are_scanned():
    import sqlite3
    target = _target({".npmrc": "//registry.npmjs.org/:_authToken=npm_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5" + "\n"})
    con = sqlite3.connect(target / "local.db")
    con.execute("create table t(k, v)")
    # Fake key assembled at runtime so no key-shaped literal sits in the repo
    # (GitHub push protection rejects realistic-looking Stripe keys).
    fake_stripe = "sk_" + "live_" + "9fK2mQ7xR4tB8nW1zL6pV3cY"
    con.execute("insert into t values ('payment', ?)", (fake_stripe,))
    con.commit(); con.close()
    rules = {f.rule_id for f in run_scan(target, modules=["secrets"], extract_archives=False).findings}
    assert {"npm-access-token", "stripe-key"} <= rules, rules


def test_binary_strings_no_cross_string_or_symbol_noise():
    from core.secrets_module import _looks_like_symbol_name, _scan_text_content
    from core.rules import load_rules
    for symbol in ("OSSL_CMP_CTX_push0_geninfo_ITAV", "PKCS12_SAFEBAG_create0_p8inf",
                   "XSetWindowBackgroundPixmap", "id-tc26-cipher-gostr3412-2015-kuznyechik"):
        assert _looks_like_symbol_name(symbol), symbol
    for token in ("aZ3k_P9xQm2_Lp7R4tN8", "Zr5nB8vKq2Wm7Tx4Lp9Hc3Qd", "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7"):
        assert not _looks_like_symbol_name(token), token
    content = "Enter password:\nReenter password:\n"
    hits = _scan_text_content(content, "x.exe", load_rules(), False, source_locations=[(0, 1), (16, 1)])
    assert not [f for f in hits if f.rule_id == "generic-password-assignment"]


def test_symbol_check_is_linear_time():
    import time
    from core.secrets_module import _looks_like_symbol_name
    start = time.time()
    _looks_like_symbol_name("abcdefghijklmnopqrstuvwxyzabcdefghij" * 4 + "+")  # was >10s: froze the UI
    assert time.time() - start < 0.1


def test_pem_header_constants_and_cert_bodies_are_not_secrets():
    from core.rules import load_rules
    from core.secrets_module import _scan_text_content
    rules = load_rules()
    headers_only = "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"
    assert not [f for f in _scan_text_content(headers_only, "x.exe", rules, True) if f.rule_id == "pem-private-key"]
    body = "MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n" * 4
    real_key = "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n"
    assert [f for f in _scan_text_content(real_key, "k.pem", rules, True) if f.rule_id == "pem-private-key"]
    cert = "-----BEGIN CERTIFICATE-----\n" + body.replace("MIIEp", "MIIC7") + "-----END CERTIFICATE-----\n"
    assert not [f for f in _scan_text_content(cert, "c.pem", rules, True) if f.rule_id == "high-entropy-string"]


def test_every_finding_has_specific_poc():
    target = _target(SECRET_FILES)
    result = run_scan(target, modules=["secrets"], extract_archives=False)
    assert all(f.poc.strip() for f in result.findings)
    aws = next(f for f in result.findings if f.rule_id == "aws-access-key-id")
    assert "Select-String" in aws.poc and aws.evidence in aws.poc and "aws-access-key-id" not in aws.poc


def test_winverifytrust_detects_tampering():
    if sys.platform != "win32":
        return
    from core.signature_module import run_winverifytrust
    src = Path(sys.executable)
    verified, _, mismatch = run_winverifytrust(src)
    if verified is None:
        return  # interpreter not signed
    assert verified and not mismatch
    tampered = Path(tempfile.mkdtemp(prefix="warden_test_")) / src.name
    data = bytearray(src.read_bytes()); data[0x400] ^= 0xFF; tampered.write_bytes(data)
    verified, _, mismatch = run_winverifytrust(tampered)
    assert verified is False and mismatch


def test_incremental_rescan_keeps_findings():
    # Default cache location lives inside the target — it must not be scanned.
    target = _target(SECRET_FILES)
    first = run_scan(target, modules=["secrets"], extract_archives=False, incremental=True)
    second = run_scan(target, modules=["secrets"], extract_archives=False, incremental=True)
    assert first.findings
    assert sorted(f.fingerprint() for f in second.findings) == sorted(f.fingerprint() for f in first.findings)


def test_cancel_stops_scan():
    def cancel(_path):
        raise ScanCancelled()

    try:
        run_scan(_target(SECRET_FILES), modules=["secrets", "dll_hijack"], extract_archives=False,
                 progress_callback=cancel)
    except ScanCancelled:
        return
    raise AssertionError("ScanCancelled was swallowed")


def test_platform_modules_do_not_duplicate_secrets():
    result = run_scan(_target(SECRET_FILES), modules=["secrets", "linux", "macos"], extract_archives=False)
    aws = [f for f in result.findings if f.rule_id == "aws-access-key-id"]
    assert len(aws) == 1, [f.module for f in aws]
    assert not any("discovered" in f.rule_id for f in result.findings)  # no "0 ELF files" noise


def test_safeseh_not_applicable_for_no_seh_dotnet():
    dll = Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Xml.dll")
    if not dll.exists():
        return
    from core.pe_utils import get_security_mitigations
    from core.re_exposure_module import _mitigation_findings
    assert "safeseh-disabled" not in {f.rule_id for f in _mitigation_findings(dll, get_security_mitigations(dll))}


def test_signature_leaf_is_real_signer():
    from core.signature_module import parse_signature
    info = parse_signature(Path(sys.executable))
    if not info.certs:
        return  # interpreter not Authenticode-signed on this platform
    assert not info.leaf.is_ca and not info.leaf.self_signed
    assert info.timestamp_present is True


def test_archive_size_cap_enforced_before_extraction():
    if archive_extractor._sevenzip_path() is None:
        return
    bomb = Path(tempfile.mkdtemp(prefix="warden_test_")) / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * (4 * 1024 * 1024))
    result = archive_extractor.extract_archive_recursive(bomb, max_total_bytes=1024 * 1024)
    try:
        assert result.truncated and not result.extracted_files
    finally:
        archive_extractor.cleanup(result)


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok ", name)
    print(f"{len(tests)} passed")
