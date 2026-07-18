#!/usr/bin/env python3
"""
Warden CLI.

Usage:
    python cli.py scan /path/to/target --output report.html
    python cli.py scan /path/to/target --json findings.json --no-entropy
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from core.logging_config import setup_logging
from core.scanner import run_scan
from report.html_export import generate_html_report

setup_logging(console=False)
console = Console()


@click.group()
def cli():
    """Warden — static security analysis for Windows thick-client apps."""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True, file_okay=False))
@click.option("--output", "-o", default="secretsentry_report.html", help="HTML report output path.")
@click.option("--json", "json_output", default=None, help="Optional path to also write raw JSON findings.")
@click.option("--rules-dir", default=None, type=click.Path(exists=True, file_okay=False), help="Override rule pack directory.")
@click.option("--no-entropy", is_flag=True, help="Disable entropy-based secret detection.")
@click.option("--no-pe-strings", is_flag=True, help="Skip scanning embedded strings inside .exe/.dll files.")
@click.option("--module", "modules", multiple=True, default=None, help="Modules to run (default: secrets). Repeatable. Options: secrets, dll_hijack, signature, re_exposure, linux, macos, reputation")
@click.option("--services-file", default=None, type=click.Path(exists=True, dir_okay=False), help="Optional text file with 'sc query'/'wmic service' output for unquoted-path checks (Module 2).")
@click.option("--no-osslsigncode", is_flag=True, help="Skip shelling out to osslsigncode for full signature verification (Module 3 structural checks still run).")
@click.option("--vt-api-key", default=None, envvar="VT_API_KEY", help="VirusTotal API key for the 'reputation' module. Can also be set via the VT_API_KEY env var. Only a SHA-256 hash is ever sent — see --vt-upload-unknown.")
@click.option("--vt-include-clean", is_flag=True, help="Also emit an Info finding for binaries VirusTotal has seen and NOT flagged (default: only flagged binaries are reported).")
@click.option("--vt-max-lookups", default=15, show_default=True, help="Cap on binaries checked per scan, to stay within VirusTotal rate/quota limits. At ~15s/lookup on the free tier, this is the main lever on how much time the reputation module adds to a scan.")
@click.option("--vt-upload-unknown", is_flag=True, help="DANGER: if a binary's hash isn't already known to VirusTotal, upload the file itself for analysis. Off by default — uploading proprietary/client binaries to a third party may violate engagement confidentiality. Only enable this if you've confirmed it's acceptable for this target.")
@click.option("--incremental", is_flag=True, help="Use the SHA-256 scan cache and skip unchanged files where supported.")
@click.option("--cache-file", default=None, type=click.Path(dir_okay=False), help="Override the incremental scan cache file.")
@click.option("--yara-rules-dir", default=None, type=click.Path(exists=True, file_okay=False), help="Custom YARA rules directory for reverse-engineering scans.")
@click.option("--plugins-dir", default=None, type=click.Path(exists=True, file_okay=False), help="Directory of Python detector plugins exposing scan_file(path).")
@click.option("--max-workers", default=1, show_default=True, help="Worker threads for file-parallel modules.")
@click.option("--hide-inventory", is_flag=True, help="Hide low-risk inventory/pass findings from Linux/macOS modules.")
def scan(target, output, json_output, rules_dir, no_entropy, no_pe_strings, modules, services_file, no_osslsigncode,
         vt_api_key, vt_include_clean, vt_max_lookups, vt_upload_unknown, incremental, cache_file,
         yara_rules_dir, plugins_dir, max_workers, hide_inventory):
    """Run a static security scan against TARGET directory."""
    selected_modules = list(modules) if modules else ["secrets"]

    console.print(f"[bold cyan]Warden[/bold cyan] scanning [white]{target}[/white]")
    console.print(f"Modules: {', '.join(selected_modules)}")

    if "reputation" in selected_modules:
        eta_seconds = vt_max_lookups * 15
        eta_minutes, eta_secs = divmod(eta_seconds, 60)
        eta_text = f"{eta_minutes}m {eta_secs}s" if eta_minutes else f"{eta_secs}s"
        console.print(
            f"[dim]reputation: worst case on the free VirusTotal tier, up to {eta_text} added "
            f"for {vt_max_lookups} lookups (~15s each). Runs after all other selected modules "
            f"finish. Lower with --vt-max-lookups if this scan doesn't need full coverage.[/dim]"
        )

    if "reputation" in selected_modules and vt_upload_unknown:
        console.print(
            "[bold yellow]Warning:[/bold yellow] --vt-upload-unknown is set — binaries not already "
            "known to VirusTotal will be uploaded there. Make sure that's acceptable for this target "
            "before continuing."
        )

    scanned = {"count": 0}

    def progress(path: str):
        scanned["count"] += 1
        if scanned["count"] % 25 == 0:
            console.print(f"  ...{scanned['count']} files scanned", style="dim")

    def on_error(message: str):
        console.print(f"  [dim]{message}[/dim]")

    try:
        result = run_scan(
            target_dir=target,
            modules=selected_modules,
            rules_dir=rules_dir,
            enable_entropy=not no_entropy,
            scan_pe_strings=not no_pe_strings,
            services_file=services_file,
            use_osslsigncode=not no_osslsigncode,
            vt_api_key=vt_api_key,
            vt_include_clean=vt_include_clean,
            vt_max_lookups=vt_max_lookups,
            vt_upload_unknown=vt_upload_unknown,
            incremental=incremental,
            cache_file=cache_file,
            yara_rules_dir=yara_rules_dir,
            plugins_dir=plugins_dir,
            max_workers=max_workers,
            include_inventory=not hide_inventory,
            progress_callback=progress,
            error_callback=on_error,
        )
    except NotImplementedError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)

    counts = result.summary_counts()
    table = Table(title="Findings Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev, count in counts.items():
        table.add_row(sev, str(count))
    console.print(table)

    html_path = generate_html_report(result, output)
    console.print(f"[bold green]HTML report written:[/bold green] {html_path}")

    if json_output:
        Path(json_output).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[bold green]JSON findings written:[/bold green] {json_output}")


if __name__ == "__main__":
    cli()
