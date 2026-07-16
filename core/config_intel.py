"""Structured configuration intelligence for common app config formats."""
from __future__ import annotations

import configparser
import json
import plistlib
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib

AUTH_KEYS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "client_secret", "auth")
DB_KEYS = ("database", "db_", "jdbc", "dsn", "connection", "mongodb", "postgres", "mysql", "sqlite")
TLS_KEYS = ("ssl", "tls", "certificate", "cert", "verify", "ca_bundle")
DEBUG_KEYS = ("debug", "trace", "verbose", "dev_mode")
LOG_KEYS = ("log", "logging", "loglevel", "log_level")


def _flatten(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            yield from _flatten(v, key)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, value


def _classify_key(key: str) -> list[str]:
    k = key.lower()
    tags = []
    if any(s in k for s in AUTH_KEYS):
        tags.append("auth-setting")
    if any(s in k for s in DB_KEYS):
        tags.append("database-setting")
    if any(s in k for s in TLS_KEYS):
        tags.append("tls-setting")
    if any(s in k for s in DEBUG_KEYS):
        tags.append("debug-setting")
    if any(s in k for s in LOG_KEYS):
        tags.append("logging-setting")
    return tags


def _interesting_value(key: str, value: Any) -> bool:
    if not _classify_key(key):
        return False
    if isinstance(value, bool):
        return True
    if value is None:
        return False
    return str(value).strip() != ""


def _parse_xml(text: str) -> dict[str, Any]:
    root = ET.fromstring(text)
    out: dict[str, Any] = {}

    def walk(node, prefix=""):
        name = f"{prefix}.{node.tag}" if prefix else node.tag
        for k, v in node.attrib.items():
            out[f"{name}@{k}"] = v
        if node.text and node.text.strip():
            out[name] = node.text.strip()
        for child in list(node):
            walk(child, name)

    walk(root)
    return out


def parse_config_file(path: Path) -> dict[str, Any] | None:
    ext = path.suffix.lower()
    try:
        if ext == ".json":
            return {"format": "JSON", "data": json.loads(path.read_text(encoding="utf-8", errors="ignore"))}
        if ext in {".yaml", ".yml"}:
            return {"format": "YAML", "data": yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore")) or {}}
        if ext in {".xml", ".config", ".manifest"}:
            return {"format": "XML", "data": _parse_xml(path.read_text(encoding="utf-8", errors="ignore"))}
        if ext in {".ini", ".conf", ".cfg", ".properties", ".env"}:
            parser = configparser.ConfigParser()
            text = path.read_text(encoding="utf-8", errors="ignore")
            if ext in {".env", ".properties"}:
                text = "[default]\n" + text
            parser.read_string(text)
            return {"format": "INI", "data": {s: dict(parser[s]) for s in parser.sections()}}
        if ext == ".toml":
            return {"format": "TOML", "data": tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))}
        if ext == ".plist":
            with open(path, "rb") as f:
                return {"format": "plist", "data": plistlib.load(f)}
        if ext in {".sqlite", ".sqlite3", ".db"}:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                rows = con.execute("select name from sqlite_master where type='table'").fetchall()
                return {"format": "SQLite", "data": {"tables": [r[0] for r in rows]}}
            finally:
                con.close()
    except Exception:
        return None
    return None


def extract_interesting_settings(path: Path) -> list[dict[str, Any]]:
    parsed = parse_config_file(path)
    if not parsed:
        return []
    results = []
    for key, value in _flatten(parsed["data"]):
        if _interesting_value(key, value):
            results.append({
                "format": parsed["format"],
                "key": key,
                "value": value,
                "tags": _classify_key(key),
            })
    return results
