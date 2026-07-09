#!/usr/bin/env python3
"""
Warden GUI — desktop wrapper around the CLI scan engine.

Lets an analyst pick a target (folder, or a single .exe/.dll), choose which
modules to run, kick off the scan, watch live progress, cancel mid-run if
needed, and have the generated HTML report open automatically when done.

Run with:  python gui.py
"""
from __future__ import annotations

import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH, DISABLED, END, LEFT, NORMAL, RIGHT, VERTICAL, X, Y,
    BooleanVar, Canvas, Frame, Label, PhotoImage, Scrollbar, StringVar, Tk, Text,
    filedialog, messagebox,
)
from tkinter import ttk

from core.scanner import run_scan
from report.html_export import generate_html_report

APP_TITLE = "Warden — Static Security Analysis"
LOGO_PATH = Path(__file__).resolve().parent / "assets" / "logo.png"


class ScanCancelled(Exception):
    """Raised inside the scan worker when the user requests cancellation."""


# --- Palette -------------------------------------------------------------
# Minimal graphite dark theme — flat neutrals with a single calm accent,
# kept deliberately low-contrast/low-saturation so it reads as a serious
# analyst tool rather than a flashy consumer app.
BG = "#101113"
PANEL = "#17181b"
PANEL_ALT = "#131416"
BORDER = "#24262a"
TEXT = "#e9eaec"
MUTED = "#8b8f96"
ACCENT = "#6d8cf0"
ACCENT_SOFT = "#93aaf3"
GREEN = "#7fb069"
AMBER = "#d0b352"
RED = "#e0645c"

UI_FONT = "Segoe UI"
MONO_FONT = "Consolas"

CARD_RADIUS = 12
BTN_RADIUS = 8
CHK_RADIUS = 5


def _round_rect(canvas: Canvas, x1, y1, x2, y2, r, **kwargs):
    """Draw a smooth rounded rectangle on a Canvas and return its item id."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    points = [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)


class RoundedCard(Frame):
    """A soft-cornered panel whose background tracks its content size."""

    def __init__(self, parent, bg_color=PANEL, border_color=BORDER, radius=CARD_RADIUS):
        super().__init__(parent, bg=BG)
        self._bg_color = bg_color
        self._border_color = border_color
        self._radius = radius
        self.canvas = Canvas(self, bg=BG, highlightthickness=0)
        self.canvas.pack(fill=BOTH, expand=True)
        self.body = Frame(self.canvas, bg=bg_color)
        self._win = self.canvas.create_window(2, 2, window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._redraw)
        self.canvas.bind("<Configure>", self._on_canvas_resize)

    def _on_canvas_resize(self, event):
        width = max(event.width - 4, 1)
        self.canvas.itemconfig(self._win, width=width)
        self._redraw()

    def _redraw(self, event=None):
        self.canvas.delete("bg")
        w = self.body.winfo_reqwidth()
        h = self.body.winfo_reqheight()
        cw = max(self.canvas.winfo_width(), w + 4)
        self.canvas.configure(height=h + 4)
        rect = _round_rect(
            self.canvas, 1, 1, cw - 1, h + 3, self._radius,
            fill=self._bg_color, outline=self._border_color, width=1, tags="bg",
        )
        self.canvas.tag_lower(rect)


_BUTTON_STYLES = {
    "primary": dict(bg=ACCENT, border=ACCENT, hover=ACCENT_SOFT, hover_border=ACCENT_SOFT,
                     fg="#11131a", disabled_bg="#33363d", disabled_border="#33363d", disabled_fg="#7a7d84"),
    "secondary": dict(bg="#1c1e22", border="#34373d", hover="#262931", hover_border="#454951",
                       fg=TEXT, disabled_bg=PANEL_ALT, disabled_border=BORDER, disabled_fg="#5c5f66"),
    "danger": dict(bg="#211a1a", border="#4a2c2b", hover="#2c1f1e", hover_border="#5c332f",
                    fg=RED, disabled_bg=PANEL_ALT, disabled_border=BORDER, disabled_fg="#5c5f66"),
}


class RoundButton(Frame):
    """A flat, rounded-corner button drawn on a Canvas for a smoother feel
    than the default square ttk button."""

    def __init__(self, parent, text, command=None, kind="secondary",
                 panel_bg=BG, padx=16, pady=10, bold=None):
        super().__init__(parent, bg=panel_bg)
        self.command = command
        self.style = _BUTTON_STYLES[kind]
        self.text = text
        self.state_ = NORMAL
        self._hover = False
        is_bold = bold if bold is not None else (kind == "primary")
        self.font = (UI_FONT, 10, "bold" if is_bold else "normal")

        probe = Label(self, text=text, font=self.font)
        probe.update_idletasks()
        w = probe.winfo_reqwidth() + padx * 2
        h = probe.winfo_reqheight() + pady * 2
        probe.destroy()
        self.w, self.h = w, h

        self.canvas = Canvas(self, width=w, height=h, bg=panel_bg, highlightthickness=0)
        self.canvas.pack()
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Enter>", self._on_enter)
        self.canvas.bind("<Leave>", self._on_leave)
        self._draw()

    def _draw(self):
        self.canvas.delete("all")
        st = self.style
        if self.state_ == DISABLED:
            fill, border, fg = st["disabled_bg"], st["disabled_border"], st["disabled_fg"]
        elif self._hover:
            fill, border, fg = st["hover"], st["hover_border"], st["fg"]
        else:
            fill, border, fg = st["bg"], st["border"], st["fg"]
        _round_rect(self.canvas, 1, 1, self.w - 1, self.h - 1, BTN_RADIUS, fill=fill, outline=border, width=1.3)
        self.canvas.create_text(self.w / 2, self.h / 2, text=self.text, fill=fg, font=self.font)

    def _on_click(self, _event=None):
        if self.state_ != DISABLED and self.command:
            self.command()

    def _on_enter(self, _event=None):
        self._hover = True
        self.canvas.configure(cursor="" if self.state_ == DISABLED else "hand2")
        self._draw()

    def _on_leave(self, _event=None):
        self._hover = False
        self._draw()

    def configure(self, state=None, text=None, **_kwargs):
        if state is not None:
            self.state_ = state
        if text is not None:
            self.text = text
        self._draw()


class BrandMark(Frame):
    """App logo — loads the bundled Warden mark, falling back to a
    canvas-drawn placeholder glyph if the asset is ever missing."""

    def __init__(self, parent, bg, size=34, accent=None, ink=None):
        super().__init__(parent, bg=bg)
        self._img = None
        try:
            img = PhotoImage(file=str(LOGO_PATH))
            self._img = img
            Label(self, image=img, bg=bg, borderwidth=0).pack()
        except Exception:
            self._draw_fallback(bg, size, accent or ACCENT, ink or "#11131a")

    def _draw_fallback(self, bg, size, accent, ink):
        s = size
        canvas = Canvas(self, width=s, height=s, bg=bg, highlightthickness=0)
        canvas.pack()
        pts = [
            0.16 * s, 0.02 * s, 0.84 * s, 0.02 * s,
            s, 0.16 * s, s, 0.46 * s,
            0.5 * s, 0.98 * s,
            0, 0.46 * s, 0, 0.16 * s,
        ]
        canvas.create_polygon(pts, smooth=True, fill=accent, outline=accent)
        canvas.create_line(
            0.22 * s, 0.30 * s, 0.36 * s, 0.62 * s, 0.5 * s, 0.40 * s,
            0.64 * s, 0.62 * s, 0.78 * s, 0.30 * s,
            fill=ink, width=max(2, round(s * 0.085)),
            capstyle="round", joinstyle="round", smooth=False,
        )


class RoundCheck(Frame):
    """A rounded checkbox with a proper checkmark glyph (not an 'x')."""

    def __init__(self, parent, text, variable: BooleanVar, bg=PANEL, size=17):
        super().__init__(parent, bg=bg)
        self.variable = variable
        self.bg = bg
        self.size = size
        self.canvas = Canvas(self, width=size, height=size, bg=bg, highlightthickness=0)
        self.canvas.pack(side=LEFT, padx=(0, 8))
        self.label = Label(self, text=text, bg=bg, fg=TEXT, font=(UI_FONT, 10))
        self.label.pack(side=LEFT)
        for widget in (self.canvas, self.label):
            widget.bind("<Button-1>", self._toggle)
            widget.bind("<Enter>", lambda e: (self.canvas.configure(cursor="hand2")))
        self.variable.trace_add("write", lambda *_a: self._draw())
        self._draw()

    def _toggle(self, _event=None):
        self.variable.set(not self.variable.get())

    def _draw(self):
        self.canvas.delete("all")
        s = self.size
        checked = self.variable.get()
        fill = ACCENT if checked else PANEL_ALT
        outline = ACCENT if checked else BORDER
        _round_rect(self.canvas, 1, 1, s - 1, s - 1, CHK_RADIUS, fill=fill, outline=outline, width=1.4)
        if checked:
            self.canvas.create_line(
                s * 0.27, s * 0.52, s * 0.43, s * 0.70, s * 0.76, s * 0.30,
                fill="#11131a", width=2, capstyle="round", joinstyle="round",
            )


class WardenGUI:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("880x780")
        self.root.configure(bg=BG)
        try:
            self.root.iconbitmap(str(Path(__file__).resolve().parent / "assets" / "logo.ico"))
        except Exception:
            pass
        self.root.minsize(760, 640)

        self.target_path = StringVar()
        self.services_file = StringVar()
        self.output_dir = StringVar(value=str(Path.cwd()))
        self.status_text = StringVar(value="● READY")
        self.progress_pct = StringVar(value="")

        self.mod_secrets = BooleanVar(value=True)
        self.mod_dll_hijack = BooleanVar(value=True)
        self.mod_signature = BooleanVar(value=True)
        self.mod_re_exposure = BooleanVar(value=True)
        self.enable_entropy = BooleanVar(value=True)
        self.scan_pe_strings = BooleanVar(value=True)
        self.use_osslsigncode = BooleanVar(value=True)

        self._scan_thread: threading.Thread | None = None
        self._msg_queue: queue.Queue = queue.Queue()
        self._last_report_path: Path | None = None
        self._cancel_event = threading.Event()

        self._build_style()
        self._build_layout()
        self._poll_queue()

    # ------------------------------------------------------------------
    # Style
    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)

        style.configure(
            "TEntry", fieldbackground=PANEL_ALT, foreground=TEXT,
            bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
            insertcolor=TEXT, borderwidth=1,
        )
        style.map("TEntry", bordercolor=[("focus", ACCENT)])

        style.configure(
            "TProgressbar", troughcolor=PANEL_ALT, background=ACCENT,
            bordercolor=PANEL_ALT, lightcolor=ACCENT, darkcolor=ACCENT,
            thickness=8,
        )

    def _card(self, parent, title=None, subtitle=None):
        """A soft rounded-corner panel section with an optional title row."""
        card = RoundedCard(parent, bg_color=PANEL, border_color=BORDER, radius=CARD_RADIUS)
        card.pack(fill=X, pady=(0, 14))
        inner = Frame(card.body, bg=PANEL)
        inner.pack(fill=BOTH, expand=True, padx=20, pady=16)
        if title:
            Label(inner, text=title, bg=PANEL, fg=TEXT, font=(UI_FONT, 11, "bold")).pack(anchor="w")
            if subtitle:
                Label(inner, text=subtitle, bg=PANEL, fg=MUTED, font=(UI_FONT, 8), wraplength=780, justify=LEFT).pack(anchor="w", pady=(2, 12))
            else:
                Frame(inner, bg=PANEL, height=8).pack()
        return inner

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_layout(self):
        # --- Header bar ---
        header = Frame(self.root, bg=PANEL_ALT)
        header.pack(fill=X)
        header_inner = Frame(header, bg=PANEL_ALT)
        header_inner.pack(fill=X, padx=24, pady=16)

        title_row = Frame(header_inner, bg=PANEL_ALT)
        title_row.pack(fill=X)
        BrandMark(title_row, bg=PANEL_ALT, size=34, accent=ACCENT).pack(side=LEFT, padx=(0, 14))
        title_col = Frame(title_row, bg=PANEL_ALT)
        title_col.pack(side=LEFT)
        Label(title_col, text="Warden", bg=PANEL_ALT, fg=TEXT, font=(UI_FONT, 17, "bold")).pack(anchor="w")
        Label(
            title_col, text="Static security analysis for Windows thick-client applications",
            bg=PANEL_ALT, fg=MUTED, font=(UI_FONT, 9),
        ).pack(anchor="w")

        self.status_pill = Label(
            title_row, textvariable=self.status_text, bg="#1c2233", fg=ACCENT_SOFT,
            font=(UI_FONT, 9, "bold"), padx=12, pady=5,
        )
        self.status_pill.pack(side=RIGHT, anchor="e")

        # --- Scrollable body ---
        outer = Frame(self.root, bg=BG)
        outer.pack(fill=BOTH, expand=True)
        canvas = Canvas(outer, bg=BG, highlightthickness=0)
        vscroll = Scrollbar(outer, orient=VERTICAL, command=canvas.yview)
        body = Frame(canvas, bg=BG)
        body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        window_id = canvas.create_window((0, 0), window=body, anchor="nw")
        canvas.configure(yscrollcommand=vscroll.set)

        def _on_resize(e):
            canvas.itemconfig(window_id, width=e.width)
        canvas.bind("<Configure>", _on_resize)

        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        vscroll.pack(side=RIGHT, fill=Y)

        pad = Frame(body, bg=BG)
        pad.pack(fill=BOTH, expand=True, padx=24, pady=18)

        # --- Target card ---
        c = self._card(pad, "1 \u00b7 TARGET", "Pick the extracted application's root folder (recommended \u2014 scans everything), or a single .exe/.dll for a quick one-file check.")
        target_row = Frame(c, bg=PANEL)
        target_row.pack(fill=X)
        ttk.Entry(target_row, textvariable=self.target_path, font=(MONO_FONT, 10)).pack(side=LEFT, fill=X, expand=True, ipady=5)
        RoundButton(target_row, "\U0001F4C1 Folder\u2026", command=self._select_folder, kind="secondary", panel_bg=PANEL).pack(side=LEFT, padx=(8, 0))
        RoundButton(target_row, "\U0001F4C4 File\u2026", command=self._select_file, kind="secondary", panel_bg=PANEL).pack(side=LEFT, padx=(6, 0))

        # --- Modules card ---
        c = self._card(pad, "2 \u00b7 MODULES", "Select which analysis modules to run.")
        grid = Frame(c, bg=PANEL)
        grid.pack(fill=X)
        mods = [
            (self.mod_secrets, "Module 1 \u2014 Secrets & Config Exposure"),
            (self.mod_dll_hijack, "Module 2 \u2014 DLL Hijacking Detection"),
            (self.mod_signature, "Module 3 \u2014 Signature / Integrity Check"),
            (self.mod_re_exposure, "Module 4 \u2014 RE / Anti-Tamper Exposure"),
        ]
        for i, (var, label) in enumerate(mods):
            RoundCheck(grid, label, var, bg=PANEL).grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 24), pady=5)

        # --- Options card ---
        c = self._card(pad, "3 \u00b7 OPTIONS")
        RoundCheck(c, "Entropy-based secret detection", self.enable_entropy, bg=PANEL).pack(anchor="w", pady=3)
        RoundCheck(c, "Scan embedded strings inside .exe/.dll", self.scan_pe_strings, bg=PANEL).pack(anchor="w", pady=3)
        RoundCheck(c, "Use osslsigncode for deep signature verification (if installed)", self.use_osslsigncode, bg=PANEL).pack(anchor="w", pady=3)

        Label(c, text="Services file (optional, Module 2 \u2014 sc query / wmic output):", bg=PANEL, fg=MUTED, font=(UI_FONT, 8)).pack(anchor="w", pady=(12, 3))
        services_row = Frame(c, bg=PANEL)
        services_row.pack(fill=X)
        ttk.Entry(services_row, textvariable=self.services_file, font=(MONO_FONT, 10)).pack(side=LEFT, fill=X, expand=True, ipady=4)
        RoundButton(services_row, "Browse\u2026", command=self._select_services_file, kind="secondary", panel_bg=PANEL).pack(side=LEFT, padx=(8, 0))

        # --- Output card ---
        c = self._card(pad, "4 \u00b7 OUTPUT")
        out_row = Frame(c, bg=PANEL)
        out_row.pack(fill=X)
        ttk.Entry(out_row, textvariable=self.output_dir, font=(MONO_FONT, 10)).pack(side=LEFT, fill=X, expand=True, ipady=5)
        RoundButton(out_row, "\U0001F4C2 Choose Folder\u2026", command=self._select_output_dir, kind="secondary", panel_bg=PANEL).pack(side=LEFT, padx=(8, 0))
        RoundButton(out_row, "\U0001F5C2\uFE0F Open Folder", command=self._open_output_folder, kind="secondary", panel_bg=PANEL).pack(side=LEFT, padx=(6, 0))

        # --- Run controls ---
        run_card = Frame(pad, bg=BG)
        run_card.pack(fill=X, pady=(0, 14))
        run_row = Frame(run_card, bg=BG)
        run_row.pack(fill=X)
        self.run_button = RoundButton(run_row, "\u25b6  Run Scan", command=self._start_scan, kind="primary", panel_bg=BG)
        self.run_button.pack(side=LEFT)
        self.cancel_button = RoundButton(run_row, "\u2715  Cancel Scan", command=self._cancel_scan, kind="danger", panel_bg=BG)
        self.cancel_button.configure(state=DISABLED)
        self.cancel_button.pack(side=LEFT, padx=(10, 0))
        self.open_report_button = RoundButton(run_row, "\U0001F310 Open Last Report", command=self._open_report, kind="secondary", panel_bg=BG)
        self.open_report_button.configure(state=DISABLED)
        self.open_report_button.pack(side=LEFT, padx=(10, 0))

        progress_row = Frame(run_card, bg=BG)
        progress_row.pack(fill=X, pady=(12, 2))
        self.progress = ttk.Progressbar(progress_row, mode="determinate", style="TProgressbar")
        self.progress.pack(side=LEFT, fill=X, expand=True)
        Label(progress_row, textvariable=self.progress_pct, bg=BG, fg=MUTED, font=(MONO_FONT, 9), width=6, anchor="e").pack(side=LEFT, padx=(8, 0))

        self.status_line = Label(run_card, text="", bg=BG, fg=MUTED, font=(MONO_FONT, 9), anchor="w")
        self.status_line.pack(fill=X, anchor="w")

        # --- Log card ---
        c = self._card(pad, "SCAN LOG")
        log_frame = Frame(c, bg="#0b0c0d", highlightbackground=BORDER, highlightthickness=1)
        log_frame.pack(fill=BOTH, expand=True)
        scrollbar = Scrollbar(log_frame, orient=VERTICAL)
        self.log_text = Text(
            log_frame, height=12, bg="#0b0c0d", fg="#b9d0a8", insertbackground=TEXT,
            font=(MONO_FONT, 9), wrap="word", yscrollcommand=scrollbar.set, borderwidth=0,
            padx=10, pady=8,
        )
        self.log_text.tag_configure("error", foreground=RED)
        self.log_text.tag_configure("warn", foreground=AMBER)
        self.log_text.tag_configure("ok", foreground=GREEN)
        self.log_text.tag_configure("dim", foreground=MUTED)
        scrollbar.config(command=self.log_text.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.log_text.pack(side=LEFT, fill=BOTH, expand=True)
        self.log_text.configure(state=DISABLED)

    # ------------------------------------------------------------------
    # File dialogs
    # ------------------------------------------------------------------
    def _select_folder(self):
        path = filedialog.askdirectory(title="Select target application folder")
        if path:
            self.target_path.set(path)

    def _select_file(self):
        path = filedialog.askopenfilename(
            title="Select a single .exe or .dll",
            filetypes=[("Windows binaries", "*.exe *.dll *.sys *.ocx"), ("All files", "*.*")],
        )
        if path:
            self.target_path.set(path)

    def _select_services_file(self):
        path = filedialog.askopenfilename(title="Select services list text file (sc query / wmic output)")
        if path:
            self.services_file.set(path)

    def _select_output_dir(self):
        path = filedialog.askdirectory(title="Select output folder for the report")
        if path:
            self.output_dir.set(path)

    def _open_output_folder(self):
        out_dir = self.output_dir.get().strip()
        if not out_dir or not Path(out_dir).exists():
            messagebox.showinfo("Warden", "Output folder does not exist yet.")
            return
        try:
            if sys.platform.startswith("win"):
                import os
                os.startfile(out_dir)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", out_dir])
            else:
                subprocess.Popen(["xdg-open", out_dir])
        except Exception as e:
            messagebox.showerror("Warden", f"Could not open folder:\n\n{e}")

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def _log(self, message: str):
        tag = None
        if message.startswith("ERROR"):
            tag = "error"
        elif message.startswith("WARNING"):
            tag = "warn"
        elif "complete" in message.lower() or "written" in message.lower():
            tag = "ok"
        self.log_text.configure(state=NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(END, f"[{timestamp}] ", "dim")
        self.log_text.insert(END, f"{message}\n", tag or ())
        self.log_text.see(END)
        self.log_text.configure(state=DISABLED)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self._msg_queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "status":
                    self.status_line.configure(text=payload)
                elif kind == "max":
                    self.progress.configure(maximum=payload)
                elif kind == "progress":
                    self.progress.configure(value=payload)
                    maximum = self.progress["maximum"] or 1
                    self.progress_pct.set(f"{int(payload / maximum * 100)}%")
                elif kind == "done":
                    self._on_scan_complete(payload)
                elif kind == "error":
                    self._on_scan_error(payload)
                elif kind == "cancelled":
                    self._on_scan_cancelled()
        except queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------
    def _validate_inputs(self) -> str | None:
        target = self.target_path.get().strip()
        if not target:
            return "Select a target folder or file first."
        if not Path(target).exists():
            return f"Target path does not exist:\n{target}"
        if not any([self.mod_secrets.get(), self.mod_dll_hijack.get(), self.mod_signature.get(), self.mod_re_exposure.get()]):
            return "Select at least one module to run."
        out_dir = self.output_dir.get().strip()
        if not out_dir or not Path(out_dir).exists():
            return "Select a valid output folder."
        return None

    def _set_status_pill(self, bg, fg):
        self.status_pill.configure(bg=bg, fg=fg)

    def _start_scan(self):
        error = self._validate_inputs()
        if error:
            messagebox.showwarning("Warden", error)
            return

        self._cancel_event.clear()
        self.run_button.configure(state=DISABLED)
        self.cancel_button.configure(state=NORMAL)
        self.open_report_button.configure(state=DISABLED)
        self.progress.configure(mode="determinate", maximum=100, value=0)
        self.progress_pct.set("0%")
        self.status_text.set("\u25cf SCANNING")
        self._set_status_pill("#1c2233", ACCENT_SOFT)
        self.status_line.configure(text="Preparing scan\u2026")
        self.log_text.configure(state=NORMAL)
        self.log_text.delete("1.0", END)
        self.log_text.configure(state=DISABLED)
        self._log("Starting scan\u2026")

        self._scan_thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        self._scan_thread.start()

    def _cancel_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._cancel_event.set()
            self.cancel_button.configure(state=DISABLED)
            self.status_line.configure(text="Cancelling\u2026 finishing current file.")
            self._log("Cancellation requested \u2014 stopping after current file.")

    def _run_scan_worker(self):
        try:
            target = self.target_path.get().strip()
            target_path = Path(target)

            scan_root = target_path if target_path.is_dir() else target_path.parent
            if target_path.is_file():
                self._msg_queue.put((
                    "log",
                    f"Single-file target selected \u2014 scanning containing folder "
                    f"'{scan_root}' so DLL/config context is included.",
                ))

            modules = []
            if self.mod_secrets.get():
                modules.append("secrets")
            if self.mod_dll_hijack.get():
                modules.append("dll_hijack")
            if self.mod_signature.get():
                modules.append("signature")
            if self.mod_re_exposure.get():
                modules.append("re_exposure")

            self._msg_queue.put(("log", f"Modules: {', '.join(modules)}"))
            self._msg_queue.put(("log", f"Target: {scan_root}"))

            from core.fs_walk import iter_target_files
            file_count = sum(1 for _ in iter_target_files(scan_root))
            total_ticks = max(file_count * len(modules), 1)
            self._msg_queue.put(("log", f"Found {file_count} eligible files \u2014 scanning with {len(modules)} module(s)\u2026"))
            self._msg_queue.put(("max", total_ticks))

            files_scanned = {"count": 0}

            def progress_callback(path_str: str):
                if self._cancel_event.is_set():
                    raise ScanCancelled()
                files_scanned["count"] += 1
                self._msg_queue.put(("progress", files_scanned["count"]))
                self._msg_queue.put(("status", f"Scanning ({files_scanned['count']}/{total_ticks}): {path_str}"))
                if files_scanned["count"] % 25 == 0:
                    self._msg_queue.put(("log", f"  ...{files_scanned['count']} files scanned \u2014 current: {path_str}"))

            def error_callback(message: str):
                self._msg_queue.put(("log", f"WARNING: {message}"))

            services_file = self.services_file.get().strip() or None

            result = run_scan(
                target_dir=scan_root,
                modules=modules,
                enable_entropy=self.enable_entropy.get(),
                scan_pe_strings=self.scan_pe_strings.get(),
                services_file=services_file,
                use_osslsigncode=self.use_osslsigncode.get(),
                progress_callback=progress_callback,
                error_callback=error_callback,
            )

            counts = result.summary_counts()
            self._msg_queue.put((
                "log",
                f"Scan complete \u2014 {result.metadata.files_scanned} files scanned. "
                f"Critical: {counts['Critical']}  High: {counts['High']}  "
                f"Medium: {counts['Medium']}  Low: {counts['Low']}  Info: {counts['Info']}",
            ))

            out_dir = Path(self.output_dir.get().strip())
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = out_dir / f"warden_report_{timestamp}.html"
            json_path = out_dir / f"warden_findings_{timestamp}.json"

            generate_html_report(result, report_path)
            import json as _json
            json_path.write_text(_json.dumps(result.to_dict(), indent=2), encoding="utf-8")

            self._msg_queue.put(("log", f"HTML report written: {report_path}"))
            self._msg_queue.put(("log", f"JSON findings written: {json_path}"))
            self._msg_queue.put(("done", {"report_path": report_path, "counts": counts}))

        except ScanCancelled:
            self._msg_queue.put(("log", "Scan cancelled by user."))
            self._msg_queue.put(("cancelled", None))
        except Exception as e:
            self._msg_queue.put(("error", str(e)))

    def _on_scan_complete(self, payload: dict):
        self.progress.configure(value=self.progress["maximum"])
        self.progress_pct.set("100%")
        self.run_button.configure(state=NORMAL)
        self.cancel_button.configure(state=DISABLED)
        self._last_report_path = payload["report_path"]
        self.open_report_button.configure(state=NORMAL)
        counts = payload["counts"]
        total_issues = counts["Critical"] + counts["High"] + counts["Medium"] + counts["Low"]
        if counts["Critical"]:
            bg, fg = "#2a1c1c", RED
        elif counts["High"]:
            bg, fg = "#2a251a", AMBER
        else:
            bg, fg = "#1a2419", GREEN
        self.status_text.set(f"\u25cf DONE \u2014 {total_issues} issues")
        self._set_status_pill(bg, fg)
        self.status_line.configure(
            text=f"Critical={counts['Critical']}  High={counts['High']}  "
                 f"Medium={counts['Medium']}  Low={counts['Low']}  Info={counts['Info']}"
        )
        self._open_report()

    def _on_scan_error(self, message: str):
        self.progress.configure(value=0)
        self.progress_pct.set("")
        self.run_button.configure(state=NORMAL)
        self.cancel_button.configure(state=DISABLED)
        self.status_text.set("\u25cf ERROR")
        self._set_status_pill("#2a1c1c", RED)
        self.status_line.configure(text="Error \u2014 see log below.")
        self._log(f"ERROR: {message}")
        messagebox.showerror("Warden", f"Scan failed:\n\n{message}")

    def _on_scan_cancelled(self):
        self.progress.configure(value=0)
        self.progress_pct.set("")
        self.run_button.configure(state=NORMAL)
        self.cancel_button.configure(state=DISABLED)
        self.status_text.set("\u25cf CANCELLED")
        self._set_status_pill("#2a251a", AMBER)
        self.status_line.configure(text="Scan cancelled \u2014 no report was generated.")

    def _open_report(self):
        if self._last_report_path and self._last_report_path.exists():
            webbrowser.open(self._last_report_path.as_uri())
        else:
            messagebox.showinfo("Warden", "No report available yet.")


def _make_dpi_aware():
    """On Windows, an app that hasn't declared DPI-awareness gets rendered
    at 96dpi and then bitmap-stretched by the OS to match display scaling
    (125%/150%/etc) — that's what causes the blurry text/buttons. Declaring
    awareness up front makes Windows hand us real pixels instead."""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main():
    _make_dpi_aware()
    root = Tk()
    try:
        # Sync Tk's own font/geometry scaling to the real screen DPI now
        # that Windows is reporting true pixels, so text/widgets come out
        # crisp at whatever scale (100%/125%/150%/...) the display uses.
        actual_dpi = root.winfo_fpixels("1i")
        root.tk.call("tk", "scaling", actual_dpi / 72.0)
    except Exception:
        pass
    WardenGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
