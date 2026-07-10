# Warden

Static security analysis tool for Windows thick-client applications — secrets
exposure, insecure configuration, DLL hijacking risk, code-signing verification,
and reverse-engineering exposure.

Built for use during authorized VAPT / thick-client assessment engagements.

## Status

**Module 1 — Secrets & Config Exposure Scanner: implemented.**
**Module 2 — DLL Hijacking Detection: implemented.**
**Module 3 — Signature / Integrity Check: implemented.**
**Module 4 — Reverse Engineering / Anti-Tamper Exposure: implemented.**
**Desktop GUI: implemented.** Every finding across all four modules
includes a detailed **Proof of Concept / Reproduction Steps** section with
concrete commands. All four core modules from the original spec are now
built.

## Module 1 — What it does

- Recursively scans `.config`, `.xml`, `.json`, `.ini`, `.env`, `.yaml`, `.sql`,
  `.reg`, and similar text/config files for hardcoded secrets.
- Extracts and scans embedded strings inside `.exe`/`.dll`/`.sys`/`.ocx` files
  (via `pefile`) for the same secret patterns — catches credentials baked into
  compiled binaries, not just config.
- Sniffs local database files (`.mdb`, `.accdb`, `.sqlite`) for plaintext
  credential/PII patterns (byte-level scan, not structured DB parsing in v1).
- Combines a YAML-based regex rule pack (gitleaks-style, see
  `rules/secrets_patterns.yaml`) with Shannon-entropy scoring to catch secrets
  that don't match a known vendor format.
- Flags world-writable files that also contain sensitive findings.
- Deduplicates findings by content fingerprint and tags low-confidence /
  placeholder-looking matches (e.g. `changeme`, `example`) so reports stay
  usable instead of drowning in noise.
- Outputs a dark ops-console styled HTML report (self-contained, no external
  assets) with unified Critical/High/Medium/Low/Info severity scoring, plus
  optional raw JSON for tooling integration.

## Module 2 — What it does

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
- **Unquoted service path**: parses `.reg` exports found anywhere under the
  target directory for `Services\...\ImagePath` values, plus an optional
  `--services-file` (paste `sc query` / `wmic service get name,pathname`
  output) and flags unquoted paths containing spaces.

## Module 3 — What it does

- Checks every `.exe`/`.dll`/`.sys`/`.ocx` for Authenticode signature
  presence (via the PE security data directory).
- Structurally parses embedded PKCS#7/certificate data (via `cryptography`,
  no dependency on Windows APIs) to flag: **unsigned binaries**, **expired
  certificates**, **self-signed certificates**, and **weak signature hash
  algorithms** (SHA-1/MD5).
- **Cross-binary publisher consistency**: flags when binaries in the same
  app are signed by more than one distinct publisher — a possible
  supply-chain inconsistency signal (also normal for bundled third-party
  redistributables, so this is reported at Low confidence for triage).
- Optionally shells out to `osslsigncode verify` (if installed) for a real
  digest/chain check. A genuine digest mismatch (evidence of tampering
  after signing) is reported as **Critical**; a chain-of-trust failure that's
  simply due to a self-signed/untrusted cert is *not* separately flagged as
  a failure, since that's already covered by the `self-signed-certificate`
  finding — this avoids double-counting the same root cause.
- **Insecure auto-update heuristic**: flags binaries containing update/
  version-check related strings with no imported API commonly used to
  verify a downloaded payload's signature (`WinVerifyTrust`,
  `CryptQueryObject`, etc.) — reported as a Low-confidence heuristic, not
  proof of an exploitable flaw.

## Module 4 — What it does

Static indicators only — no dynamic/runtime analysis, no bypass tooling. This
module identifies *exposure*, not exploitation.

- **Assembly Security Analysis** (the "Get-PESecurity" checklist): checks
  every PE's `OPTIONAL_HEADER.DllCharacteristics` and load-config directory
  for **ASLR** (`/DYNAMICBASE`, plus `/HIGHENTROPYVA` on 64-bit), **DEP/NX**
  (`/NXCOMPAT`), **SafeSEH** (`/SAFESEH`, 32-bit only), and **Control Flow
  Guard** (`/GUARD:CF`). Missing ASLR/DEP are High severity; missing
  SafeSEH/CFG are Medium.
- **Packer detection**: known packer/protector section-name signatures
  (UPX, Themida, VMProtect, ASPack, etc. — see
  `rules/packer_signatures.yaml`) plus a section-entropy fallback for
  unrecognized packers.
- **.NET obfuscation check**: for `.NET` assemblies (detected via
  `mscoree.dll` import), flags when no known obfuscator marker is present
  **and** the binary references license/activation/crypto-key keywords —
  i.e. sensitive logic sitting in trivially-decompilable IL.
- **PDB / debug symbol leakage**: flags binaries embedding a full local
  build-machine path to their `.pdb`, which commonly leaks developer
  usernames and internal directory structure.
- **Anti-debug API presence**: informational only — flags binaries with no
  `IsDebuggerPresent`/`CheckRemoteDebuggerPresent`/etc. references, as a
  maturity signal, not a vulnerability.

## Usage

```bash
pip install -r requirements.txt

# All four implemented modules
python cli.py scan /path/to/extracted/app \
    --module secrets --module dll_hijack --module signature --module re_exposure \
    --services-file sc_query_output.txt \
    --output report.html \
    --json findings.json

# Module 3 without shelling out to osslsigncode (structural checks only)
python cli.py scan /path/to/extracted/app --module signature --no-osslsigncode

# Module 1 only (default)
python cli.py scan /path/to/extracted/app --output report.html
```

> **Optional system dependency**: Module 3's deeper digest verification uses
> `osslsigncode` if it's installed (`apt install osslsigncode` on
> Debian/Ubuntu/Kali). Without it, Module 3 still runs full structural
> certificate checks — you just won't get the digest-mismatch/tampering
> check, and can pass `--no-osslsigncode` to skip the attempt explicitly.

## Desktop GUI

For analysts who'd rather not use the CLI: `python gui.py` opens a desktop
window where you can:

1. Select a target folder (recommended) or a single `.exe`/`.dll`.
2. Tick which modules to run (Modules 1-4, all implemented) and any options
   (entropy detection, PE string scanning, osslsigncode use, an optional
   services-file for Module 2).
3. Click **Run Scan** — progress and a live log stream in the window.
4. The generated HTML report opens automatically in your browser when the
   scan finishes; a JSON export is written alongside it in the chosen
   output folder.

```bash
python gui.py
```

Requires the same dependencies as the CLI (`pip install -r requirements.txt`)
plus Tkinter, which ships with the standard python.org Windows installer by
default (no extra install needed on Windows).

## Proof of Concept in reports

Every finding — across all three modules — now includes a **Proof of
Concept / Reproduction Steps** section in addition to Evidence/Description/
Remediation, with concrete commands to independently reproduce the finding:
`icacls`/`Get-AuthenticodeSignature` invocations for signature and
permission findings, Process Monitor filter setup and PoC-DLL placement
steps for DLL hijacking findings, and `Select-String`/`strings` commands
plus rotation guidance for secrets findings. This is meant to match the
level of detail expected in a client-facing VAPT report body, not just a
one-line "unsigned binary" or "phantom DLL" statement.

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
secretsentry/
├── core/
│   ├── scanner.py             # orchestrator — merges module output
│   ├── secrets_module.py      # Module 1 (implemented)
│   ├── dll_hijack_module.py   # Module 2 (implemented)
│   ├── signature_module.py    # Module 3 (implemented)
│   ├── re_exposure_module.py  # Module 4 (implemented)
│   ├── models.py              # Finding / Severity / ScanMetadata schema
│   ├── rules.py                # YAML rule pack loader (secrets)
│   ├── entropy.py              # Shannon entropy scoring
│   ├── pe_utils.py             # shared PE parsing (pefile wrapper)
│   └── fs_walk.py              # file walking, extension filtering, perms
├── rules/
│   ├── secrets_patterns.yaml
│   ├── system_dlls.yaml       # known Windows system DLLs (Module 2)
│   └── packer_signatures.yaml # packer sections + .NET obfuscator markers (Module 4)
├── report/
│   └── html_export.py
├── cli.py
└── README.md
```

`core/pe_utils.py` and `core/fs_walk.py` are intentionally shared, generic
modules — Module 2 (DLL hijacking) and Module 4 (RE exposure) will reuse the
same PE parsing (`parse_pe`) and file-walking helpers rather than duplicating
them.

## Known limitations (v1 / Module 1)

- **ACL inspection**: on non-Windows hosts (the typical case — this tool
  usually runs on the analyst's Linux/Kali workstation against an extracted
  install tree), only POSIX permission bits are checked as a proxy signal.
  Full Windows DACL/SACL analysis requires running on Windows with `pywin32`
  or a manual `icacls` follow-up — flagged as an Info-level finding when hit.
- **Local database scanning** is a raw byte-level scan for now, not a
  structured SQLite/Access parse — sufficient to catch obvious plaintext
  credentials but won't inspect encrypted or structured binary fields.
- **Entropy detection** is a heuristic catch-all and will produce more false
  positives than the regex rules; entropy-only findings are marked with
  `confidence: Low` so they're easy to filter in the JSON output or visually
  distinguish in the HTML report.
- Environment-leftover detection (`Debug=true`, `Environment=Staging` style
  flags) and unified cross-module severity weighting are planned as
  extensions to this module but not yet built.

## Known limitations (Module 2)

- **Known-system-DLL list is not exhaustive.** `rules/system_dlls.yaml` covers
  common Windows DLLs but unusual-yet-legitimate system DLLs may be flagged
  as phantom imports; these findings are marked `confidence: Medium` for
  manual triage rather than dropped.
- **Search-order exposure detection is import-presence based, not
  flag-aware.** It checks whether safe-loading APIs are imported at all, not
  whether `LoadLibraryEx` is actually called with `LOAD_LIBRARY_SEARCH_*`
  flags (that requires disassembly of call sites, deferred to a future pass).
- **Unquoted service path detection depends on available input.** If no
  `.reg` export exists under the target directory and no `--services-file`
  is supplied, this check silently finds nothing — it does not query a live
  registry itself (static-analysis-only, per the tool's design).
- **ACL/writable-directory check** shares the same POSIX-vs-Windows caveat as
  Module 1 (see above).

## Known limitations (Module 3)

- **Full Authenticode chain-of-trust validation is best done on Windows.**
  This module always does its own structural certificate parsing (works
  identically on any OS), and additionally shells out to `osslsigncode
  verify` when that tool is installed for a real digest check. Neither path
  replicates Windows' own trust store / revocation (CRL/OCSP) checking —
  for a definitive verdict, run `signtool verify /pa` on a Windows host.
- **osslsigncode chain-of-trust failures are deliberately not treated as
  "verification failed" findings** unless there's an actual digest
  mismatch, to avoid double-flagging every self-signed certificate as both
  `self-signed-certificate` and a separate Critical failure. If you need
  the raw `osslsigncode` output for a binary, it's available in the JSON
  export path (not currently surfaced in the HTML report to keep it
  readable — happy to add if useful).
- **The auto-update heuristic is intentionally conservative and noisy-safe**:
  it only looks at import presence, not whether a verification API is
  actually called on the update-download code path. Treat it as a lead for
  manual review, not a finding to act on directly.
- **Timestamp (RFC3161) validation is not performed** — an expired
  certificate on a properly timestamped signature may still be valid per
  Windows' own rules; this module flags expiry as a hygiene signal
  regardless of timestamping.

## Known limitations (Module 4)

- **Packer detection is signature-based, not behavioral.** Known packer
  section names (UPX, Themida, VMProtect, etc. in
  `rules/packer_signatures.yaml`) and a section-entropy fallback will miss
  novel or custom packers that use unrecognized section names and
  deliberately-lowered entropy to evade this exact heuristic.
- **.NET obfuscation detection is marker-based.** It looks for known
  commercial obfuscator signature strings; a custom/in-house obfuscator
  with no matching marker would not be detected, and the "sensitive logic"
  trigger is keyword-based (license/crypto/activation terms) rather than a
  real control-flow/data-flow analysis of what the code actually does.
- **SafeSEH detection only applies to 32-bit binaries** — 64-bit Windows
  uses table-based structured exception handling and doesn't use the
  SafeSEH mechanism, so this check is correctly skipped (not flagged as
  missing) for 64-bit targets.
- **This module reports exposure, not exploitability.** A missing
  mitigation (e.g. no CFG) only matters if there's an actual memory-
  corruption bug to exploit; treat these findings as "raises the ceiling
  on exploit difficulty if a bug is found elsewhere," not standalone
  vulnerabilities.
- **Anti-debug API absence is informational only** and intentionally
  scored at Info severity — it is a reverse-engineering-effort signal, not
  a security control gap, and this module does not generate or suggest
  anti-debug bypass code per the project's static-analysis-only scope.

## Legal / Ethical Use

Warden is a **static-analysis-only** tool. It is intended strictly for
authorized VAPT engagements against applications you own or have explicit
written client consent to assess. It performs no dynamic exploitation,
runtime instrumentation, or anti-tamper bypass. Do not use this tool against
systems you do not have authorization to test.
