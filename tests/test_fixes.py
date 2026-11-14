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


def test_reports_grouped_by_application_name():
    from desktop.main_window import _app_name
    assert _app_name(r"C:\Program Files\Rockstar Games\Launcher\Launcher.exe") == "Launcher"
    assert _app_name(r"C:\Apps\Acme Suite") == "Acme Suite"
    assert _app_name(r"C:\x\bad<name>.dll") == "bad_name_"


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
    # Default cache location lives inside the target - it must not be scanned.
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


def test_asar_is_unpacked():
    import struct
    body = b"const apiKey = 1;\n"
    index = json.dumps({"files": {"main.js": {"offset": "0", "size": len(body)},
                                  "..": {"files": {"evil.js": {"offset": "0", "size": 1}}}}}).encode()
    pad = (4 - len(index) % 4) % 4
    header = struct.pack("<IIII", 4, len(index) + 8 + pad, len(index) + 4 + pad, len(index)) + index + b"\0" * pad
    asar = Path(tempfile.mkdtemp(prefix="warden_test_")) / "app.asar"
    asar.write_bytes(header + body)
    dest = asar.parent / "out"
    assert archive_extractor._extract_asar(asar, dest)
    assert (dest / "main.js").read_bytes() == body
    assert not (asar.parent / "evil.js").exists()  # crafted index cannot escape


def test_binary_noise_filters():
    from core.re_exposure_module import _looks_like_plausible_domain
    from core.rules import load_rules
    for junk in ("ENE.cN", "OIw.dE", "N1O.FR", "fRa.ch"):
        assert not _looks_like_plausible_domain(junk), junk
    for real in ("Muldersoft.com", "gmx.de", "crl.microsoft.com"):
        assert _looks_like_plausible_domain(real), real
    rules = {r.id: r.pattern for r in load_rules()}
    assert not rules["generic-password-assignment"].search("password:!0,range:!0,search:!0")
    assert rules["generic-password-assignment"].search("password = P%ssw0rd!Real")
    from core.secrets_module import _looks_like_lookup_table, _scan_text_content
    for table in ("0123456789abcdefABCDEFxX+-pPiInN", "bcdfghiklmnoprstuvwxyz", "000102030405060708090a0b0c0d0e0f"):
        assert _looks_like_lookup_table(table), table
    assert not _looks_like_lookup_table("aZ3k_P9xQm2_Lp7R4tN8")
    label = _scan_text_content("x={password`:`Show password`}\n", "a.js", load_rules(), False)
    assert not [f for f in label if f.rule_id == "generic-password-assignment"]
    assert not rules["internal-url"].search("https://react.dev/errors/")
    assert rules["internal-url"].search("https://api.dev.acme.com/x")


def test_poc_for_bundled_file_is_runnable():
    from core.path_utils import localize_poc
    tmp = r"C:\T\warden_extract_ab\$PLUGINSDIR\app-64.7z__unpacked\resources\app.asar__unpacked\main.js"
    poc = localize_poc(f"1. Location: {tmp}\n2. dumpbin \"{tmp}\"", tmp, "x > y", r"C:\Dl\Setup.exe", r"C:\Dl")
    assert "7z x 'Setup.exe' -o'warden_extracted'" in poc
    assert "npx --yes @electron/asar extract" in poc and 'dumpbin "$f"' in poc and "warden_extract_ab" not in poc


def test_electron_fuses_and_webpreferences():
    from core import electron_checks as ec
    exe = Path(tempfile.mkdtemp(prefix="warden_test_")) / "App.exe"
    blob = b"MZ" + ec.FUSE_SENTINEL + bytes([1, 8]) + b"10000100" + b" Chrome/120.0.1.2 Electron/28.0.0 "
    rules = {f.rule_id for f in ec.check_runtime(exe, blob, signed=False)}
    assert {"electron-fuse-runasnode", "electron-fuse-asar-integrity-off", "outdated-electron-runtime"} <= rules, rules
    assert "electron-asar-integrity-unsigned" not in rules  # integrity is OFF here: separate finding
    hard = {f.rule_id for f in ec.check_runtime(exe, blob.replace(b"10000100", b"00001100"), signed=False)}
    assert "electron-fuse-runasnode" not in hard and "electron-asar-integrity-unsigned" in hard

    root = exe.parent / "app"; root.mkdir()
    (root / "package.json").write_text('{"main": "main.js"}')
    (root / "main.js").write_text(
        "const w = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: !1 } });\n"
        "w.loadURL('https://x');\n")
    found = {f.rule_id: f for f in ec.check_app_sources(root.parent)}
    assert {"electron-node-integration", "electron-context-isolation-off", "electron-navigation-unrestricted"} <= set(found)
    assert found["electron-node-integration"].line_number == 1


def test_outdated_nsis_and_nonprod_api():
    from core.pe_utils import PEInfo
    from core.re_exposure_module import _outdated_installer_finding
    from core.rules import load_rules
    info = PEInfo(path="x.exe", is_valid_pe=True)
    info.manifest_xml = "<description>Nullsoft Install System v3.04</description>"
    assert _outdated_installer_finding(Path("x.exe"), info).rule_id == "outdated-nsis-installer"
    info.manifest_xml = "<description>Nullsoft Install System v3.10</description>"
    assert _outdated_installer_finding(Path("x.exe"), info) is None
    rule = {r.id: r.pattern for r in load_rules()}["non-production-api-endpoint"]
    assert rule.search('"https://ab12.execute-api.ap-south-1.amazonaws.com/int/pos"')
    assert not rule.search('"https://ab12.execute-api.ap-south-1.amazonaws.com/prod/pos"')


def test_js_identifiers_and_api_sets_are_not_noise():
    from core.dll_hijack_module import _phantom_dll_findings
    from core.pe_utils import PEInfo
    from core.rules import load_rules
    from core.secrets_module import _scan_text_content
    js = "e._Conv3DBackpropFilterV2=function(){};t=a.UNSAFE_componentWillReceiveProps==null;\n"
    assert not [f for f in _scan_text_content(js, "a.js", load_rules(), True) if f.rule_id == "high-entropy-string"]
    info = PEInfo(path="x.exe", is_valid_pe=True)
    info.imported_dlls = ["api-ms-win-core-path-l1-1-0.dll", "bthprops.cpl", "acme_private_helper.dll"]
    names = [f.title for f in _phantom_dll_findings(Path("x.exe"), info, set(), set())]
    assert names == ["Unbundled DLL import: acme_private_helper.dll"], names


def test_inventory_excluded_from_counts():
    target = _target({"app.config": 'aws_key = AKIAIOSFODNN7ABCDEFG\n'})
    result = run_scan(target, modules=["secrets"], extract_archives=False)
    inv = Finding("re_exposure", "binary-dependency-graph", "t", Severity.INFO, str(target / "a.exe"), "KERNEL32.dll")
    result.inventory.append(inv)
    data = result.to_dict()
    assert data["inventory"] and all(f["rule_id"] != "binary-dependency-graph" for f in data["findings"])
    assert sum(data["summary"]["info_unique"].values()) == sum(f["severity"] == "Info" for f in data["findings"])


_DOTNET_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dotnet"


def test_dotnet_vulnerable_assembly_detected():
    import pytest  # noqa
    from core import dotnet_checks
    if not dotnet_checks._HAVE_DNFILE:
        return
    for exe in ("VulnClient.exe", "VulnRelease.exe"):  # debug + release IL forms
        rules = {f.rule_id for f in dotnet_checks.check_assembly(_DOTNET_FIXTURES / exe)}
        assert {"dotnet-insecure-deserialization", "dotnet-weak-crypto", "dotnet-remoting-server",
                "dotnet-tls-validation-disabled", "dotnet-weak-tls-protocol"} <= rules, (exe, rules)
        tls = next(f for f in dotnet_checks.check_assembly(_DOTNET_FIXTURES / exe)
                   if f.rule_id == "dotnet-tls-validation-disabled")
        assert tls.severity == Severity.HIGH and "cwe-295" in tls.tags


def test_dotnet_safe_assembly_no_high_findings():
    from core import dotnet_checks
    if not dotnet_checks._HAVE_DNFILE:
        return
    findings = dotnet_checks.check_assembly(_DOTNET_FIXTURES / "SafeClient.exe")
    # Safe: Aes, DataContractJson, Tls12, a real cert validator. Only the
    # Low "review" note is acceptable; nothing Medium or High.
    assert not [f for f in findings if f.severity in (Severity.HIGH, Severity.MEDIUM)], \
        [(f.severity.value, f.rule_id) for f in findings]
    assert all(f.rule_id == "dotnet-custom-cert-validation" for f in findings), \
        [f.rule_id for f in findings]


def test_dotnet_trust_all_requires_wiring_not_just_true_getter():
    # SafeClient has always-true property-style methods but no trust-all
    # wiring, so the HIGH trust-all rule must not fire on it.
    from core import dotnet_checks
    if not dotnet_checks._HAVE_DNFILE:
        return
    rules = {f.rule_id for f in dotnet_checks.check_assembly(_DOTNET_FIXTURES / "SafeClient.exe")}
    assert "dotnet-tls-validation-disabled" not in rules


def test_clr_directory_detects_modern_dotnet():
    from core.pe_utils import parse_pe
    info = parse_pe(_DOTNET_FIXTURES / "VulnClient.exe")
    assert info.is_valid_pe and info.is_dotnet
    # A native PE (the Python launcher) must not be flagged managed.
    native = parse_pe(Path(sys.executable))
    assert native.is_valid_pe and not native.is_dotnet


_JAVA_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "java"


def test_java_vulnerable_jar_detected():
    from core.java_checks import scan_tree
    jar = _JAVA_FIXTURES / "VulnApp.jar"
    rules = {f.rule_id for f in scan_tree(jar.parent, single_file=jar)}
    assert {"java-tls-trustmanager-trust-all", "java-tls-hostname-verifier-disabled",
            "java-weak-cipher", "java-weak-hash", "java-insecure-deserialization",
            "java-hardcoded-db-credentials"} <= rules, rules
    tm = next(f for f in scan_tree(jar.parent, single_file=jar) if f.rule_id == "java-tls-trustmanager-trust-all")
    assert tm.severity == Severity.HIGH and "cwe-295" in tm.tags


def test_java_safe_class_clean():
    from core.java_checks import check_class
    data = (_JAVA_FIXTURES / "SafeJava.class").read_bytes()
    # AES/GCM, SHA-256, parameterized SQL, no custom trust manager -> nothing.
    assert check_class(data, "SafeJava.class") == []


def test_java_trust_all_needs_empty_body_not_just_a_trustmanager():
    # SafeJava references no TrustManager; a verify()-shaped method returning
    # false must not be flagged. Guard against the returns-true matcher.
    from core.java_checks import _returns_true, _is_empty_void
    assert _returns_true(b"\x04\xac") and not _returns_true(b"\x03\xac")  # true vs false
    assert _is_empty_void(b"\xb1") and not _is_empty_void(b"\x2a\xb1")    # return vs aload+return


def test_inno_setup_detection_warning_and_routing():
    from core import archive_extractor as ax
    if ax._sevenzip_path() is None:
        return
    tmp = Path(tempfile.mkdtemp(prefix="warden_test_"))
    inno = tmp / "Setup.exe"
    inno.write_bytes(b"MZ" + b"\x00" * 128 + b"Inno Setup Setup Data (6.2.0)" + b"\x00" * 64)
    assert ax._is_inno_setup(inno)
    assert not ax._is_inno_setup(Path(sys.executable))  # native PE

    # 1. innoextract absent -> coverage-gap warning, nothing extracted.
    saved_path, saved_extract = ax._innoextract_path, ax._extract_inno
    try:
        ax._innoextract_path = lambda: None
        r = ax.extract_archive_recursive(inno)
        assert not r.extracted_files
        assert any("Inno Setup installer" in w and "innoextract" in w for w in r.warnings), r.warnings
        ax.cleanup(r)

        # 2. innoextract present -> payload is kept (not deleted as PE sections).
        def fake_extract(tool, archive, dest, timeout):
            (Path(dest) / "AppMain.exe").write_bytes(b"MZ payload")
            return True
        ax._innoextract_path = lambda: "innoextract"
        ax._extract_inno = fake_extract
        r2 = ax.extract_archive_recursive(inno)
        names = {p.name for p in r2.extracted_files}
        assert "AppMain.exe" in names, names
        ax.cleanup(r2)
    finally:
        ax._innoextract_path, ax._extract_inno = saved_path, saved_extract


if __name__ == "__main__":
    import logging
    logging.disable(logging.CRITICAL)
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok ", name)
    print(f"{len(tests)} passed")
