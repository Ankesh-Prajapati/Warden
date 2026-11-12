"""
Electron application checks (static).

Two inputs, because an Electron app is two things:
- the runtime executable: its build-time *fuses* (a fixed byte block after a
  sentinel) and its Electron/Chromium version;
- the main-process JavaScript (from app.asar or resources/app): BrowserWindow
  webPreferences, navigation guards, certificate and permission handling.

Each finding names the misconfiguration and its consequence, with the exact
fuse byte offset or file:line as evidence. Controls that are present are
collected into one inventory item so the report also shows what is hardened.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from core.models import Finding, Severity
from core.rules import component_thresholds

FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
# Order is fixed by Electron's fuse schema v1.
FUSE_NAMES = (
    "RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments", "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot", "GrantFileProtocolExtraPrivileges",
)
_VERSION_RE = re.compile(rb"Chrome/(\d+)\.\d+\.\d+\.\d+ Electron/(\d+)\.(\d+)\.(\d+)")
_MAX_JS_BYTES = 5 * 1024 * 1024


def read_fuses(data: bytes) -> tuple[int, dict[str, bool]] | None:
    """(offset of the first fuse byte, {fuse: enabled}) or None if not Electron.
    Layout after the sentinel: version byte, count byte, one '0'/'1' per fuse."""
    i = data.find(FUSE_SENTINEL)
    if i == -1:
        return None
    start = i + len(FUSE_SENTINEL)
    if len(data) < start + 2 or data[start] != 1:
        return None
    count = data[start + 1]
    raw = data[start + 2:start + 2 + count]
    fuses = {name: raw[n] == 0x31 for n, name in enumerate(FUSE_NAMES[:count]) if raw[n] in (0x30, 0x31)}
    return start + 2, fuses


def _finding(rule_id, title, severity, path, evidence, description, remediation, poc, **kw) -> Finding:
    return Finding(module="re_exposure", rule_id=rule_id, title=title, severity=severity, file_path=str(path),
                   evidence=evidence, description=description, remediation=remediation, poc=poc,
                   tags=["electron"] + kw.pop("tags", []), confidence=kw.pop("confidence", "High"), **kw)


_FUSE_RISKS = {
    # fuse: (enabled-is-bad, rule, title, severity, consequence, fix)
    "RunAsNode": (True, "electron-fuse-runasnode", "Electron RunAsNode fuse enabled: app binary runs arbitrary Node.js",
                  Severity.MEDIUM,
                  "Setting ELECTRON_RUN_AS_NODE=1 turns this executable into a plain Node.js interpreter. A local attacker "
                  "can run any script under the application's identity (and, once signed, its trust), bypassing "
                  "application allow-listing and EDR attribution."),
    "EnableNodeOptionsEnvironmentVariable": (True, "electron-fuse-node-options",
                  "Electron NODE_OPTIONS fuse enabled: code injection via environment variable", Severity.MEDIUM,
                  "NODE_OPTIONS (e.g. --require) is honoured, so anyone who can set the process environment can preload "
                  "arbitrary code into the main process."),
    "EnableNodeCliInspectArguments": (True, "electron-fuse-inspect",
                  "Electron --inspect fuse enabled: debugger can attach to the main process", Severity.MEDIUM,
                  "--inspect/--inspect-brk are honoured, exposing a V8 debugger that executes arbitrary code in the "
                  "privileged main process."),
    "EnableEmbeddedAsarIntegrityValidation": (False, "electron-fuse-asar-integrity-off",
                  "Electron ASAR integrity validation disabled: app code can be modified undetected", Severity.MEDIUM,
                  "app.asar is loaded without checking its hash, so anyone with write access to the install folder "
                  "can backdoor the application's JavaScript."),
    "OnlyLoadAppFromAsar": (False, "electron-fuse-load-outside-asar",
                  "Electron OnlyLoadAppFromAsar disabled: app can be loaded from a planted folder", Severity.MEDIUM,
                  "Electron also looks for resources/app or default_app, so a planted directory is loaded instead of the "
                  "integrity-checked app.asar."),
}


def check_runtime(exe: Path, data: bytes, signed: bool) -> list[Finding]:
    """Fuse and version findings for an Electron runtime executable."""
    parsed = read_fuses(data)
    if parsed is None:
        return []
    offset, fuses = parsed
    findings: list[Finding] = []
    state = ", ".join(f"{k}={'ON' if v else 'OFF'}" for k, v in fuses.items())
    poc_base = (
        "1. Read the fuse block (npm package @electron/fuses):\n"
        f"     npx --yes @electron/fuses read --app \"{exe}\"\n"
        "2. Or inspect the bytes directly (PowerShell):\n"
        f"     $b = [IO.File]::ReadAllBytes(\"{exe}\"); [Text.Encoding]::ASCII.GetString($b, 0x{offset:X}, {len(fuses)})\n"
        f"   One character per fuse, in order {', '.join(FUSE_NAMES[:len(fuses)])} ('1' = ON).\n"
        f"3. Observed: {state}"
    )
    for fuse, (bad_when_on, rule, title, severity, consequence) in _FUSE_RISKS.items():
        if fuse in fuses and fuses[fuse] == bad_when_on:
            findings.append(_finding(
                rule, title, severity, exe,
                f"Fuse {fuse}={'ON' if fuses[fuse] else 'OFF'} at file offset 0x{offset + FUSE_NAMES.index(fuse):X}",
                consequence,
                f"Flip the fuse at package time with @electron/fuses (flipFuses: {fuse}: {'false' if bad_when_on else 'true'}).",
                poc_base, offset=offset + FUSE_NAMES.index(fuse), tags=["fuse"],
            ))
    if fuses.get("EnableEmbeddedAsarIntegrityValidation") and not signed:
        findings.append(_finding(
            "electron-asar-integrity-unsigned",
            "ASAR integrity validation ineffective: Electron executable is not code-signed",
            Severity.MEDIUM, exe,
            "EnableEmbeddedAsarIntegrityValidation=ON, but the executable has no Authenticode signature",
            "The expected app.asar hash is stored inside the executable itself. Because the executable is unsigned, "
            "an attacker who can write to the install folder can modify app.asar and patch the stored hash to match, "
            "so the integrity check gives no protection.",
            "Authenticode-sign the Electron executable (and installer) so the embedded integrity hash cannot be altered "
            "without breaking the signature.",
            poc_base + f"\n4. Confirm the executable is unsigned:\n     Get-AuthenticodeSignature \"{exe}\" | Format-List Status",
            tags=["fuse", "integrity", "signature"],
        ))
    m = _VERSION_RE.search(data)
    if m:
        chrome, electron = int(m.group(1)), tuple(int(x) for x in m.group(2, 3, 4))
        floor = int(component_thresholds().get("electron_min_supported_major", 0))
        version = ".".join(map(str, electron))
        if electron[0] < floor:
            findings.append(_finding(
                "outdated-electron-runtime",
                f"Outdated Electron runtime {version} (Chromium {chrome}): unpatched browser/V8 vulnerabilities",
                Severity.MEDIUM, exe, m.group(0).decode(),
                f"Electron {electron[0]} is out of support (oldest supported major: {floor}). Its bundled Chromium/V8 "
                "no longer receives security fixes, so publicly known renderer and V8 vulnerabilities apply to any "
                "content the app renders.",
                "Upgrade to a supported Electron release and keep it on the current stable line.",
                f"1. Show the embedded version string:\n     strings64.exe -n 8 \"{exe}\" | findstr /c:\"Electron/\"\n"
                f"2. Expected: {m.group(0).decode()} (supported majors: {floor} and later).",
                tags=["outdated-component"],
            ))
        state += f"; Electron {version} (Chromium {chrome})"
    findings.append(_finding(
        "electron-hardening-summary", "Electron runtime fuses", Severity.INFO, exe, state,
        "Build-time fuse configuration of the Electron runtime.", "", poc_base, tags=["inventory"],
    ))
    return findings


# --- main-process JavaScript ------------------------------------------------

_BOOL = r"\s*:\s*(true|false|!0|!1)"
_PREFS = {
    # option: (insecure value, rule, title, severity, consequence)
    "nodeIntegration": (True, "electron-node-integration", "Renderer has Node.js access (nodeIntegration: true)",
                        Severity.HIGH, "Any script that runs in the window (XSS, a malicious ad, a compromised CDN "
                        "asset) can call require('child_process') and execute commands: XSS becomes RCE."),
    "nodeIntegrationInSubFrames": (True, "electron-node-integration-subframes",
                        "Node.js enabled in sub-frames (nodeIntegrationInSubFrames: true)", Severity.HIGH,
                        "Embedded iframes get Node.js access, so third-party framed content can execute commands."),
    "nodeIntegrationInWorker": (True, "electron-node-integration-worker",
                        "Node.js enabled in web workers (nodeIntegrationInWorker: true)", Severity.MEDIUM,
                        "Web workers started by page script get Node.js access."),
    "contextIsolation": (False, "electron-context-isolation-off", "Context isolation disabled (contextIsolation: false)",
                        Severity.HIGH, "Page script shares the JavaScript context with the preload script, so it can "
                        "tamper with preload globals and reach the privileged APIs exposed there (and Node.js when "
                        "the preload has it)."),
    "sandbox": (False, "electron-sandbox-off", "Renderer sandbox disabled (sandbox: false)", Severity.MEDIUM,
                "The renderer runs outside Chromium's OS sandbox, so a renderer exploit is not contained and the "
                "preload script runs with full Node.js."),
    "webSecurity": (False, "electron-web-security-off", "Same-origin policy disabled (webSecurity: false)",
                    Severity.HIGH, "The window can read responses from any origin and load file:// content, "
                    "turning any injected script into a cross-origin data-theft and local-file-read primitive."),
    "allowRunningInsecureContent": (True, "electron-insecure-content", "Mixed content allowed (allowRunningInsecureContent: true)",
                    Severity.MEDIUM, "HTTPS pages may load scripts over plain HTTP, which a network attacker can replace."),
    "webviewTag": (True, "electron-webview-enabled", "<webview> tag enabled (webviewTag: true)", Severity.LOW,
                   "Page script can create <webview> elements with their own (possibly weaker) preferences."),
    "enableRemoteModule": (True, "electron-remote-module", "Legacy remote module enabled (enableRemoteModule: true)",
                           Severity.HIGH, "The renderer can call main-process modules directly through 'remote'."),
}
_SWITCHES = {
    "ignore-certificate-errors": ("electron-ignore-cert-errors", "TLS certificate validation disabled (--ignore-certificate-errors)",
                                  Severity.HIGH, "Every HTTPS connection accepts any certificate, so network traffic "
                                  "(including tokens and API data) can be intercepted and modified."),
    "disable-web-security": ("electron-disable-web-security", "Same-origin policy disabled (--disable-web-security)",
                             Severity.HIGH, "All windows ignore the same-origin policy."),
}


def _line_of(text: str, pos: int) -> tuple[int, str]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:end if end != -1 else len(text)].strip()
    return text.count("\n", 0, pos) + 1, (line[:200] + "…") if len(line) > 200 else line


def _js_poc(path: Path, line: int, needle: str) -> str:
    return (
        f"1. Open the main-process file and go to line {line}:\n     {path}\n"
        f"2. Or search it:\n     Select-String -Path \"{path}\" -SimpleMatch -Pattern \"{needle}\"\n"
        "3. If the app ships app.asar, extract it first: npx --yes @electron/asar extract app.asar app_src"
    )


def _braced(text: str, open_pos: int) -> str:
    depth = 0
    for i in range(open_pos, min(len(text), open_pos + 4000)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos:i + 1]
    return text[open_pos:open_pos + 4000]


def check_main_process_file(path: Path, text: str) -> tuple[list[Finding], list[str]]:
    """(findings, hardening controls seen) for one main-process JS file."""
    findings: list[Finding] = []
    controls: list[str] = []
    if "Content-Security-Policy" in text:
        controls.append(f"Content-Security-Policy header set ({path.name})")
    if "safeStorage" in text:
        controls.append(f"secrets encrypted with safeStorage/DPAPI ({path.name})")
    if "BrowserWindow" not in text and "app.commandLine" not in text:
        return findings, controls

    for m in re.finditer(r"webPreferences\s*:\s*\{", text):
        block = _braced(text, m.end() - 1)
        for opt, (bad, rule, title, severity, consequence) in _PREFS.items():
            v = re.search(rf"\b{opt}{_BOOL}", block)
            if not v:
                continue
            value = v.group(1) in ("true", "!0")
            line, code = _line_of(text, m.end() - 1 + v.start())
            if value == bad:
                findings.append(_finding(rule, title, severity, path, f"{path.name}:{line}: {code}", consequence,
                                         f"Set {opt}: {'false' if bad else 'true'} in every BrowserWindow's webPreferences.",
                                         _js_poc(path, line, opt), line_number=line, tags=["webpreferences"]))
            else:
                controls.append(f"{opt}: {str(value).lower()} ({path.name}:{line})")

    for switch, (rule, title, severity, consequence) in _SWITCHES.items():
        for m in re.finditer(rf"appendSwitch\(\s*[\"'`]{switch}[\"'`]", text):
            line, code = _line_of(text, m.start())
            findings.append(_finding(rule, title, severity, path, f"{path.name}:{line}: {code}", consequence,
                                     f"Remove the '{switch}' command-line switch.", _js_poc(path, line, switch),
                                     line_number=line, tags=["command-line"]))

    for m in re.finditer(r"[\"'`]certificate-error[\"'`]", text):
        handler = text[m.end():m.end() + 600]
        if re.search(r"callback\(\s*(true|!0)\s*\)", handler) and "preventDefault" in handler:
            line, code = _line_of(text, m.start())
            findings.append(_finding(
                "electron-certificate-error-accepted", "TLS certificate errors accepted (certificate-error handler trusts all)",
                Severity.HIGH, path, f"{path.name}:{line}: {code}",
                "The certificate-error handler calls callback(true), so invalid or attacker-issued certificates are "
                "accepted and HTTPS traffic can be intercepted.",
                "Do not override certificate errors; pin the expected certificate/key instead if needed.",
                _js_poc(path, line, "certificate-error"), line_number=line, tags=["tls"]))

    for m in re.finditer(r"setPermissionRequestHandler\(", text):
        handler = text[m.end():m.end() + 300]
        if re.search(r"callback\(\s*(true|!0)\s*\)", handler):
            line, code = _line_of(text, m.start())
            findings.append(_finding(
                "electron-permissions-auto-granted", "All web permission requests auto-granted (camera, mic, geolocation…)",
                Severity.MEDIUM, path, f"{path.name}:{line}: {code}",
                "Any page loaded in the app silently receives every permission it asks for.",
                "Grant only the specific permissions the app needs, and only for the app's own origin.",
                _js_poc(path, line, "setPermissionRequestHandler"), line_number=line, tags=["permissions"]))
        elif "callback(" in handler:
            controls.append(f"permission requests filtered ({path.name})")

    if "new BrowserWindow" in text and re.search(r"\.load(URL|File)\(", text):
        missing = []
        if "will-navigate" not in text:
            missing.append("will-navigate (in-window navigation)")
        if "setWindowOpenHandler" not in text and "new-window" not in text:
            missing.append("setWindowOpenHandler (window.open / target=_blank)")
        if missing:
            m = re.search(r"new BrowserWindow", text)
            line, code = _line_of(text, m.start())
            findings.append(_finding(
                "electron-navigation-unrestricted", "Window navigation not restricted: app can be steered to attacker content",
                Severity.MEDIUM, path, f"{path.name}:{line}: {code}; no handler for: " + ", ".join(missing),
                "Nothing stops a link, redirect or injected script from navigating the window (or opening a new one) "
                "to an attacker-controlled site, which then runs with the window's preload APIs and permissions.",
                "Add webContents.on('will-navigate', e => allowlist check / e.preventDefault()) and "
                "setWindowOpenHandler(() => ({ action: 'deny' })), opening external links via shell.openExternal "
                "with an allowlist.",
                _js_poc(path, line, "new BrowserWindow"), line_number=line, tags=["navigation"],
                confidence="Medium"))
        else:
            controls.append(f"navigation and window-open restricted ({path.name})")
    return findings, controls


def _app_roots(target_dir: Path) -> list[Path]:
    roots = []
    for pkg in target_dir.rglob("package.json"):
        if "node_modules" in pkg.parts:
            continue
        try:
            meta = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(meta, dict) and isinstance(meta.get("main"), str):
            roots.append(pkg.parent)
    return roots


def check_app_sources(target_dir: Path) -> list[Finding]:
    """Main-process checks for every Electron app root (package.json with "main")."""
    findings: list[Finding] = []
    for root in _app_roots(target_dir):
        controls: list[str] = []
        for js in root.rglob("*"):
            if js.suffix.lower() not in (".js", ".cjs", ".mjs") or "node_modules" in js.parts:
                continue
            try:
                if js.stat().st_size > _MAX_JS_BYTES:
                    continue
                text = js.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            got, seen = check_main_process_file(js, text)
            findings.extend(got)
            controls.extend(seen)
        if controls:
            findings.append(_finding(
                "electron-hardening-summary", "Electron main-process hardening controls", Severity.INFO,
                root / "package.json", "; ".join(dict.fromkeys(controls)),
                "Security controls verified in the main-process code.", "", "", tags=["inventory"]))
    return findings
