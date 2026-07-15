# Warden

Static security analysis for thick-client desktop applications — Windows,
Linux, and macOS. Hardcoded secrets and config exposure, DLL/library hijack
risk, code-signing verification, reverse-engineering/anti-tamper exposure,
and optional VirusTotal reputation checks, all from a single native desktop
app or CLI.

Built for use during authorized VAPT / thick-client assessment engagements.

**Author:** Ankesh Prajapati

---

## Contents

- [What it is](#what-it-is)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Desktop app](#desktop-app)
- [CLI](#cli)
- [Modules](#modules)
- [VirusTotal reputation checks](#virustotal-reputation-checks)
- [Extending detection rules](#extending-detection-rules)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [Legal / Ethical use](#legal--ethical-use)

---

## What it is

Warden is a **static-analysis-only** tool: it reads files, it never executes
the target application, instruments it at runtime, or attempts to bypass
any protection it finds. Point it at an extracted install tree (or a single
binary) and it walks every file, running whichever modules you select:

| Module | Platform | What it looks for |
|---|---|---|
| Secrets & Config Exposure | All | Hardcoded credentials in config files and compiled binaries |
| DLL Hijacking Detection | Windows | Search-order planting, phantom DLL imports, unquoted service paths |
| Signature / Integrity Check | Windows | Missing/expired/self-signed certs, weak hash algorithms, tampering |
| RE / Anti-Tamper Exposure | Windows | Missing ASLR/DEP/CFG, packers, PDB path leaks, obfuscation gaps |
| Linux Thick-Client Assessment | Linux | ELF hardening, systemd/cron persistence, package metadata, bundled certs |
| macOS Thick-Client Assessment | macOS | Mach-O/code-signing, LaunchAgents/Daemons, entitlements, Keychain usage |
| VirusTotal Reputation Check | All | Cross-references binary hashes against VirusTotal (opt-in, hash-only by default) |

Two interfaces, one engine underneath both — the desktop app and the CLI
both call the same `core/scanner.py::run_scan()` and produce the same
self-contained HTML report (plus optional JSON) with unified
Critical/High/Medium/Low/Info severity scoring, deduplicated findings, and
a **Proof of Concept / Reproduction Steps** section on every finding with
concrete, copy-pasteable commands.

## Installation

Requires **Python 3.10+**.

### Windows

```powershell
git clone <repo-url> Warden
cd Warden
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Optional: for the Signature module's deepest check, install
[`osslsigncode`](https://github.com/mtrojnar/osslsigncode) and make sure
it's on your `PATH`. Without it, that module still runs its full
structural certificate checks — you only lose the digest-mismatch/
tampering check.

### Linux (Debian/Ubuntu/Kali)

```bash
git clone <repo-url> Warden
cd Warden
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional, for the Signature module's deepest check:
sudo apt install osslsigncode
```

The desktop app needs a display; if you're on a headless box, use the
[CLI](#cli) instead, or run PySide6 with `QT_QPA_PLATFORM=offscreen` for
automation (no window will actually render).

### macOS

```bash
git clone <repo-url> Warden
cd Warden
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional:
brew install osslsigncode
```

### Verify it installed correctly

```bash
python cli.py scan --help
```

If that prints the CLI's help text, the engine and its dependencies
(`pefile`, `PyYAML`, `click`, `rich`, `cryptography`) are installed
correctly. `PySide6` (the desktop app's only extra dependency) installs
from the same `requirements.txt` — if `python desktop/main.py` fails to
open a window, re-check that step specifically; everything else in this
project has no other native/system dependency beyond the optional
`osslsigncode` binary above.

## Quick start

```bash
# Desktop app
python desktop/main.py

# CLI — Secrets module only (the default), against a folder
python cli.py scan /path/to/extracted/app --output report.html

# CLI — every Windows-common module, plus a services dump for the DLL Hijacking module
python cli.py scan /path/to/extracted/app \
    --module secrets --module dll_hijack --module signature --module re_exposure \
    --services-file sc_query_output.txt \
    --output report.html --json findings.json
```

## Desktop app

`python desktop/main.py` opens a window where you can:

1. Select a target folder (recommended — scans everything under it) or a
   single `.exe`/`.dll` via native folder/file pickers.
2. Tick which modules to run — common modules (Secrets, DLL Hijacking,
   Signature, RE/Anti-Tamper), platform-specific modules (Linux, macOS),
   and an optional VirusTotal reputation check — plus scan options
   (entropy detection, PE string scanning, osslsigncode use, an optional
   services-file for the DLL hijacking module).
3. Click **Run Scan** — progress and a live log stream in the window;
   scanning runs on a background thread, so the UI never freezes, and
   **Cancel** actually takes effect promptly.
4. Findings land in a sortable, filterable results table; double-click any
   row for full detail (description, evidence, code context, remediation,
   PoC). The generated HTML report opens automatically when the scan
   finishes, with a JSON export available alongside it.

Built on **PySide6** (the official Qt-for-Python binding, LGPL-licensed —
safe for commercial/client-facing distribution) rather than Tkinter, for a
native look on Windows/macOS/Linux and a widget set suited to a data-heavy
security tool (sortable tables, proper dialogs, responsive background
threading). See [`desktop/README.md`](desktop/README.md) for the internal
architecture breakdown.

Settings (last-used target, module selections, options, VirusTotal key) are
remembered between runs via the OS's native settings storage — the registry
on Windows, a plist on macOS, a config file on Linux.

## CLI

```bash
python cli.py scan TARGET [OPTIONS]
```

| Option | Description |
|---|---|
| `--output, -o PATH` | HTML report output path (default: `secretsentry_report.html`) |
| `--json PATH` | Also write raw JSON findings to this path |
| `--module NAME` | Module to run — repeatable. Options: `secrets`, `dll_hijack`, `signature`, `re_exposure`, `linux`, `macos`, `reputation`. Default: `secrets` only |
| `--rules-dir PATH` | Override the rule pack directory |
| `--no-entropy` | Disable entropy-based secret detection |
| `--no-pe-strings` | Skip scanning embedded strings inside `.exe`/`.dll` |
| `--services-file PATH` | Text file with `sc query`/`wmic service` output, for the DLL Hijacking module's unquoted-path check |
| `--no-osslsigncode` | Skip shelling out to `osslsigncode` (Signature module structural checks still run) |
| `--vt-api-key KEY` | VirusTotal API key for the `reputation` module (or set the `VT_API_KEY` env var) |
| `--vt-include-clean` | Also emit an Info finding for binaries VirusTotal has seen and **not** flagged |
| `--vt-max-lookups N` | Cap on binaries checked per scan (default: 40) — stays within free-tier rate/quota limits |
| `--vt-upload-unknown` | **Uploads file content**, not just a hash, for binaries VirusTotal hasn't seen before — off by default, see [below](#virustotal-reputation-checks) |

## Modules

### Secrets & Config Exposure

- Recursively scans `.config`, `.xml`, `.json`, `.ini`, `.env`, `.yaml`, `.sql`,
  `.reg`, and similar text/config files for hardcoded secrets.
- Extracts and scans embedded strings inside `.exe`/`.dll`/`.sys`/`.ocx` files
  (via `pefile`) for the same secret patterns — catches credentials baked into
  compiled binaries, not just config.
- Sniffs local database files (`.mdb`, `.accdb`, `.sqlite`) for plaintext
  credential/PII patterns (byte-level scan, not structured DB parsing).
- Combines a YAML-based regex rule pack (gitleaks-style, see
  `rules/secrets_patterns.yaml`) with Shannon-entropy scoring to catch secrets
  that don't match a known vendor format.
- Flags world-writable files that also contain sensitive findings.
- Deduplicates findings by content fingerprint; downgrades confidence on
  placeholder-looking matches (`changeme`, `example`, etc.) and — separately
  — suppresses matches that are themselves regex pattern literals (so
  scanning a target that ships its own credential-detection rules, or
  Warden's own `rules/` directory, doesn't self-trigger false positives).
- Outputs a dark ops-console styled HTML report (self-contained, no external
  assets) with unified severity scoring, plus optional raw JSON.

### DLL Hijacking Detection (Windows)

- Enumerates PE import tables (`pefile`) across every `.exe`/`.dll`/`.sys`/`.ocx`
  under the target directory.
- **DLL search-order exposure**: flags binaries that call `LoadLibrary(Ex)`
  with no evidence of `SetDllDirectory`/`SetDefaultDllDirectories`/
  `AddDllDirectory` — the classic precondition for search-order planting.
- **Phantom DLL detection**: flags imports that resolve to neither a known
  Windows system DLL (see `rules/system_dlls.yaml`) nor a file physically
  present in the scanned app directory — a missing dependency an attacker
  could plant.
- **Writable install directory**: flags binaries sitting in a world-writable
  directory (classic hijack/replacement precondition).
- **Unquoted service path**: parses `.reg` exports found under the target
  directory for `Services\...\ImagePath` values, plus an optional
  `--services-file` (paste `sc query` / `wmic service get name,pathname`
  output), and flags unquoted paths containing spaces.

### Signature / Integrity Check (Windows)

- Checks every `.exe`/`.dll`/`.sys`/`.ocx` for Authenticode signature
  presence (via the PE security data directory).
- Structurally parses embedded PKCS#7/certificate data (via `cryptography`,
  no dependency on Windows APIs) to flag: **unsigned binaries**, **expired
  certificates**, **self-signed certificates**, and **weak signature hash
  algorithms** (SHA-1/MD5).
- **Cross-binary publisher consistency**: flags when binaries in the same
  app are signed by more than one distinct publisher (Low confidence — also
  normal for bundled third-party redistributables).
- Optionally shells out to `osslsigncode verify` (if installed) for a real
  digest/chain check. A genuine digest mismatch (evidence of tampering
  after signing) is reported as **Critical**.
- **Insecure auto-update heuristic**: flags binaries containing
  update/version-check strings with no imported API commonly used to verify
  a downloaded payload's signature (`WinVerifyTrust`, `CryptQueryObject`,
  etc.) — reported as a Low-confidence heuristic.

### RE / Anti-Tamper Exposure (Windows)

Static indicators only — no dynamic/runtime analysis, no bypass tooling.
This module identifies *exposure*, not exploitation.

- **Assembly Security Analysis**: checks every PE's `DllCharacteristics`
  and load-config directory for **ASLR**, **DEP/NX**, **SafeSEH**
  (32-bit only), and **Control Flow Guard**. Missing ASLR/DEP are High
  severity; missing SafeSEH/CFG are Medium.
- **Packer detection**: known packer/protector section-name signatures
  (UPX, Themida, VMProtect, ASPack, etc. — see
  `rules/packer_signatures.yaml`) plus a section-entropy fallback.
- **.NET obfuscation check**: for `.NET` assemblies, flags when no known
  obfuscator marker is present **and** the binary references
  license/activation/crypto-key keywords.
- **PDB / debug symbol leakage**: flags binaries embedding a full local
  build-machine path to their `.pdb`.
- **Anti-debug API presence**: informational only — a maturity signal, not
  a vulnerability.

### Linux Thick-Client Assessment

Statically assesses an extracted/installed Linux desktop application
tree — **not** the host OS itself. Covers:

Application discovery (`.desktop` files, dpkg/rpm package metadata,
discovered ELF executables) · binary analysis (ELF header facts, PIE/NX
hardening flags, embedded strings → URLs/IPs/emails/endpoints) ·
configuration file inventory · sensitive data discovery (reuses the
Secrets module's rule+entropy engine) · local database and log file
inventory + secret scan · bundled certificate analysis (expired/self-
signed/weak) · update-mechanism analysis (URLs, HTTPS usage,
signature-verify hints) · world-writable app/config/cache/log paths ·
linked shared-library inventory · internal-host/dev-staging URL discovery ·
platform-specific persistence (systemd units, cron jobs, startup scripts).

### macOS Thick-Client Assessment

Statically assesses an extracted/installed macOS `.app` bundle — **not**
the host OS itself. Covers:

Application discovery (`Info.plist` metadata) · binary analysis (Mach-O
header facts, embedded strings, code-signing status) · plist/config file
inventory · sensitive data discovery (reuses the Secrets module's engine) ·
local database and log file inventory + secret scan · bundled certificate
analysis · update-mechanism analysis (Sparkle feed URL, HTTPS, EdDSA
signature hints) · world-writable bundle/config/cache/log paths · linked
dylib and embedded Framework inventory · internal-host/dev-staging URL
discovery · platform-specific persistence and permissions (LaunchAgents/
Daemons, entitlements, Keychain usage).

## VirusTotal reputation checks

Cross-references every binary Warden finds against VirusTotal, so known-bad
files get flagged even if nothing else in the static analysis caught them.

**Hash lookup only, by default.** Only the SHA-256 of each binary is sent
to VirusTotal's `/files/{hash}` endpoint — the binary itself never leaves
the machine running Warden. This matters because the binaries under
assessment are frequently a client's proprietary, unreleased software
under NDA; silently uploading them to a public third-party service would
be a confidentiality problem independent of the security question.

Uploading unknown files for fresh analysis (`--vt-upload-unknown` /
the desktop app's "Upload unknown binaries" toggle) is a **separate,
explicit opt-in** you have to choose per scan — off by default, with a
visible warning and a second confirmation step in the desktop app, and
never remembered across sessions.

### Setup

1. Create a free account at [virustotal.com](https://www.virustotal.com)
   and verify your email.
2. Profile icon → **API Key** → copy the key shown there.
3. Paste it into the desktop app's VirusTotal panel (click **Test Key** to
   confirm it works before running a scan) or pass it via `--vt-api-key` /
   the `VT_API_KEY` environment variable for the CLI.

**Free tier limits**: 4 requests/minute, 500/day, ~15,500/month. Warden
throttles automatically to stay within this — a scan with many binaries
just takes longer, it won't fail or get your key banned. A results cap
(`--vt-max-lookups`, default 40) keeps one large scan from burning through
a whole day's quota by itself.

## Extending detection rules

Add or edit YAML files under `rules/`. Each rule:

```yaml
- id: my-custom-rule
  description: "Human-readable name shown in the report"
  regex: 'your-python-regex-here'
  severity: High   # Critical | High | Medium | Low
  tags: [custom]
```

Multiple rule pack files in the same directory are merged; duplicate rule IDs
are skipped with a warning.

## Architecture

```
Warden/
├── core/
│   ├── scanner.py             # orchestrator — merges module output, per-module error isolation
│   ├── secrets_module.py      # Secrets & Config Exposure
│   ├── dll_hijack_module.py   # DLL Hijacking Detection (Windows)
│   ├── signature_module.py    # Signature / Integrity Check (Windows)
│   ├── re_exposure_module.py  # RE / Anti-Tamper Exposure (Windows)
│   ├── linux_module.py        # Linux thick-client assessment
│   ├── macos_module.py        # macOS thick-client assessment
│   ├── reputation_module.py   # VirusTotal hash-lookup reputation checks (opt-in)
│   ├── virustotal_utils.py    # VT API v3 client — hash lookup by default, upload is separate opt-in
│   ├── models.py              # Finding / Severity / ScanMetadata schema
│   ├── rules.py                # YAML rule pack loader (secrets)
│   ├── entropy.py              # Shannon entropy scoring
│   ├── pe_utils.py             # shared PE parsing (pefile wrapper)
│   ├── binary_utils.py         # shared ELF/Mach-O parsing (Linux/macOS modules)
│   ├── cert_utils.py           # shared bundled-certificate analysis (Linux/macOS modules)
│   ├── indicator_utils.py      # shared URL/IP/email/endpoint extraction from strings
│   ├── fs_walk.py              # file walking, extension filtering, perms, symlink exclusion
│   └── logging_config.py       # centralized rotating-file logging used by cli.py and desktop/
├── desktop/                   # PySide6 GUI — see desktop/README.md
│   ├── main.py
│   ├── main_window.py
│   ├── scan_worker.py
│   ├── finding_dialog.py
│   ├── settings.py
│   └── theme.py
├── rules/
│   ├── secrets_patterns.yaml
│   ├── system_dlls.yaml       # known Windows system DLLs (DLL Hijacking module)
│   └── packer_signatures.yaml # packer sections + .NET obfuscator markers (RE Exposure module)
├── report/
│   └── html_export.py
├── cli.py
└── README.md
```

`core/pe_utils.py` and `core/fs_walk.py` are intentionally shared, generic
modules — every PE-touching module reuses the same PE parsing (`parse_pe`)
and file-walking helpers rather than duplicating them. Similarly,
`core/binary_utils.py` (ELF/Mach-O parsing) and `core/cert_utils.py`
(bundled certificate analysis) are shared between the Linux and macOS
modules, and every module reuses `core/secrets_module.py`'s rule+entropy
engine for its own sensitive-data checks rather than re-implementing it.

Two entry points, one engine: `cli.py` and `desktop/main.py` both call
`core/scanner.py::run_scan()` and `report/html_export.py` directly — no
scanning logic lives in either interface layer.

## Known limitations

**Secrets & Config Exposure**
- ACL inspection on non-Windows hosts (the typical case — this tool
  usually runs on the analyst's own Linux/Kali/macOS workstation against
  an extracted install tree) only checks POSIX permission bits as a proxy
  signal; full Windows DACL/SACL analysis needs a Windows host and
  `icacls`. Reported as an Info-level finding when this limitation is hit.
- Local database scanning is a raw byte-level scan, not a structured
  SQLite/Access parse — catches obvious plaintext credentials but won't
  inspect encrypted or structured binary fields.
- Entropy detection is a heuristic catch-all and produces more false
  positives than the regex rules; entropy-only findings are marked
  `confidence: Low`.

**DLL Hijacking Detection**
- The known-system-DLL list (`rules/system_dlls.yaml`) is not exhaustive;
  unusual-but-legitimate system DLLs may be flagged as phantom imports —
  marked `confidence: Medium` for manual triage rather than dropped.
- Search-order exposure detection is import-presence based, not
  flag-aware — it checks whether safe-loading APIs are imported at all,
  not whether `LoadLibraryEx` is actually called with the right flags at
  each call site (would need disassembly).
- Unquoted service path detection depends on available input — if no
  `.reg` export exists under the target and no `--services-file` is
  supplied, this check silently finds nothing rather than querying a live
  registry (this tool is static-analysis-only by design).

**Signature / Integrity Check**
- Full Authenticode chain-of-trust validation (including revocation/CRL/
  OCSP checking) is best done on Windows with `signtool verify /pa`; this
  module's structural parsing and optional `osslsigncode` digest check
  don't replicate that.
- `osslsigncode` chain-of-trust failures are deliberately not treated as
  separate "verification failed" findings unless there's an actual digest
  mismatch, to avoid double-flagging every self-signed cert.
- RFC3161 timestamp validation is not performed — a properly timestamped
  signature with an expired cert may still be valid per Windows' own
  rules; this module flags expiry as a hygiene signal regardless.

**RE / Anti-Tamper Exposure**
- Packer detection is signature-based (known section names + entropy
  fallback) and will miss novel/custom packers using unrecognized names
  and deliberately lowered entropy.
- .NET obfuscation detection is marker-based; a custom in-house obfuscator
  with no matching signature won't be detected.
- SafeSEH detection only applies to 32-bit binaries (64-bit Windows uses
  table-based SEH and doesn't use the mechanism — correctly not flagged).
- Findings here report *exposure*, not exploitability — a missing
  mitigation only matters if there's an actual bug to exploit elsewhere.

**VirusTotal Reputation Check**
- Hash-lookup mode can only tell you about binaries VirusTotal has seen
  before; a genuinely novel/unreleased binary will come back "unknown,"
  which is neutral information, not a clean bill of health.
- Subject to VirusTotal's own detection accuracy — treat a flag as a lead
  to investigate, and rule out known false-positive packers before
  escalating, per the finding's own remediation guidance.

## Legal / Ethical Use

Warden is a **static-analysis-only** tool. It is intended strictly for
authorized VAPT engagements against applications you own or have explicit
written client consent to assess. It performs no dynamic exploitation,
runtime instrumentation, or anti-tamper bypass. Do not use this tool against
systems you do not have authorization to test.
