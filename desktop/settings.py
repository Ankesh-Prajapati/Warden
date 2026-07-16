"""
Persisted user settings for the Warden desktop app.

Wraps QSettings so the rest of the app deals in plain Python types instead
of QVariant plumbing, and so there's one place that knows the on-disk
format if it ever needs to change.
"""
from __future__ import annotations

import json

from PySide6.QtCore import QSettings

ORG_NAME = "Ankesh Prajapati"
APP_NAME = "Warden"

DEFAULT_MODULES = ["secrets", "dll_hijack", "signature", "re_exposure"]


class WardenSettings:
    def __init__(self):
        self._qs = QSettings(ORG_NAME, APP_NAME)

    # -- generic helpers ----------------------------------------------
    def _get_json(self, key: str, default):
        raw = self._qs.value(key, None)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return default

    def _set_json(self, key: str, value) -> None:
        self._qs.setValue(key, json.dumps(value))

    # -- scan configuration ---------------------------------------------
    @property
    def last_target(self) -> str:
        return self._qs.value("scan/target", "", str)

    @last_target.setter
    def last_target(self, value: str) -> None:
        self._qs.setValue("scan/target", value)

    @property
    def last_services_file(self) -> str:
        return self._qs.value("scan/services_file", "", str)

    @last_services_file.setter
    def last_services_file(self, value: str) -> None:
        self._qs.setValue("scan/services_file", value)

    @property
    def selected_modules(self) -> list[str]:
        return self._get_json("scan/modules", DEFAULT_MODULES)

    @selected_modules.setter
    def selected_modules(self, value: list[str]) -> None:
        self._set_json("scan/modules", value)

    @property
    def enable_entropy(self) -> bool:
        return self._qs.value("scan/enable_entropy", True, bool)

    @enable_entropy.setter
    def enable_entropy(self, value: bool) -> None:
        self._qs.setValue("scan/enable_entropy", value)

    @property
    def scan_pe_strings(self) -> bool:
        return self._qs.value("scan/scan_pe_strings", True, bool)

    @scan_pe_strings.setter
    def scan_pe_strings(self, value: bool) -> None:
        self._qs.setValue("scan/scan_pe_strings", value)

    @property
    def use_osslsigncode(self) -> bool:
        return self._qs.value("scan/use_osslsigncode", True, bool)

    @use_osslsigncode.setter
    def use_osslsigncode(self, value: bool) -> None:
        self._qs.setValue("scan/use_osslsigncode", value)

    @property
    def include_inventory(self) -> bool:
        return self._qs.value("scan/include_inventory", True, bool)

    @include_inventory.setter
    def include_inventory(self, value: bool) -> None:
        self._qs.setValue("scan/include_inventory", value)

    @property
    def vt_api_key(self) -> str:
        # Stored via QSettings same as everything else here — this means
        # plaintext in the registry (Windows) / plist (macOS) / config file
        # (Linux), the same place any desktop app's "remember this API key"
        # feature would put it. Flagged in the UI label next to the input
        # so this tradeoff isn't hidden from the analyst.
        return self._qs.value("vt/api_key", "", str)

    @vt_api_key.setter
    def vt_api_key(self, value: str) -> None:
        self._qs.setValue("vt/api_key", value)

    @property
    def vt_include_clean(self) -> bool:
        return self._qs.value("vt/include_clean", False, bool)

    @vt_include_clean.setter
    def vt_include_clean(self, value: bool) -> None:
        self._qs.setValue("vt/include_clean", value)

    # -- window state -----------------------------------------------------
    def save_geometry(self, geometry: bytes) -> None:
        self._qs.setValue("window/geometry", geometry)

    def load_geometry(self):
        return self._qs.value("window/geometry", None)
