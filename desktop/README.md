# Warden Desktop (PySide6)

Warden's only graphical interface. The old Tkinter GUI (`gui.py`) and the
Flask-based web UI (`webapp/`) have both been removed — this is it.

## Why PySide6

- **Native look** on Windows, macOS, and Linux without extra theming work,
  and a modern widget set (splitters, sortable/filterable tables, proper
  dialogs) that Tkinter doesn't have out of the box.
- **Responsive UI under load** — scanning runs on a `QThread`
  (`desktop/scan_worker.py`), so the window never freezes on a large
  target, and Cancel actually takes effect promptly.
- **LGPL licensing** (PySide6, the official Qt-for-Python binding) is
  safe for both open-source and commercial/client-facing distribution,
  unlike GPL-licensed PyQt.
- **Maintainability** — Qt's signal/slot model keeps the worker thread,
  the main window, and settings persistence cleanly decoupled instead of
  the callback-heavy style Tkinter tends to encourage.

## Run it

```
pip install -r requirements.txt
python desktop/main.py
```

## Architecture

```
desktop/
  main.py             Entry point — QApplication setup + global exception hook
  main_window.py      MainWindow: target/module/option config, results table, log, VirusTotal panel
  scan_worker.py       QThread wrapper around core.scanner.run_scan, plus the VT key-test worker
  finding_dialog.py    Detail popup for a single finding (double-click a row)
  settings.py          QSettings wrapper — remembers last target/modules/options/VT key
  theme.py              Qt stylesheet (dark, matches the brand used elsewhere)
```

Same engine as everywhere else: `core/scanner.py` → `report/html_export.py`.
No scanning logic lives in the UI layer.

## Stability

- Every scan runs through `ScanWorker.run()`, which catches all exceptions
  and reports them via a Qt signal rather than letting them propagate —
  a scan failure shows a dialog, it doesn't crash the app.
- `main.py` installs a global `sys.excepthook` so even a bug outside the
  worker (a UI callback, a report-writing error) surfaces as a message
  box with the detail logged to `~/.warden/logs/warden.log`, instead of a
  silent exit.
- All scan activity, per-module timing, and non-fatal per-file errors are
  logged via `core/logging_config.py` (rotating file handler, 5MB × 5
  files) — useful for reconstructing what happened on an analyst's
  machine after the fact.

## Settings & data locations

- Window geometry and last-used scan config: OS-native `QSettings` store
  (registry on Windows, plist on macOS, config file on Linux).
- Logs: `~/.warden/logs/warden.log`
- Reports: `<Warden application folder>/reports/warden_report_<timestamp>.{html,json}`
