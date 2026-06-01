"""
plugin_loader.py — Arc 12 phase 69. Hot-load third-party bouncer adapters.

Drop a Python file into ~/.config/protek/adapters/ (or the dir named by
PROTEK_PLUGIN_DIR), restart Protek — the adapter shows up at /bouncers
without needing to fork Protek itself.

Contract for plugin authors:

    # ~/.config/protek/adapters/sophos.py
    from bouncers import register

    @register("sophos")
    class SophosBouncer:
        kind = "sophos"
        name = ""

        def __init__(self, name: str, **config):
            self.name = name
            self.api_key = config["api_key"]
            ...

        def is_configured(self) -> bool: ...
        def health(self) -> dict: ...
        def snapshot(self) -> list[dict]: ...
        def apply(self, to_add, to_remove_ids) -> dict: ...

        # Optional class-level manifest (introspected by /bouncers UI):
        PROTEK_MANIFEST = {
            "author":   "name@example.com",
            "version":  "1.0.0",
            "required": ["api_key", "endpoint"],
            "summary":  "Sophos XG firewall web-filtering address list",
        }

Loaded plugins are tracked in MANIFESTS so the UI can show provenance
(author / version / where on disk) — operator can audit what's loaded
without grepping the filesystem.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger("protek.plugin_loader")

DEFAULT_DIR = Path(os.path.expanduser("~/.config/protek/adapters"))


def plugin_dir() -> Path:
    override = os.environ.get("PROTEK_PLUGIN_DIR", "").strip()
    return Path(override) if override else DEFAULT_DIR


# Populated as plugins are loaded — keyed by kind (matches `@register("kind")`)
MANIFESTS: dict[str, dict[str, Any]] = {}


def _load_one(path: Path) -> None:
    """Import a single .py file as a plugin module. Records manifest if present."""
    mod_name = f"protek_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            log.warning("plugin %s: could not build import spec", path)
            return
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:  # noqa: BLE001
        log.warning("plugin %s failed to load: %s", path, e)
        return
    # Discover any classes that have `.kind` set (the @register decorator sets it)
    # and read their PROTEK_MANIFEST if present.
    for attr in dir(mod):
        cls = getattr(mod, attr, None)
        if not isinstance(cls, type):
            continue
        kind = getattr(cls, "kind", None)
        if not kind or not isinstance(kind, str):
            continue
        # Check it's actually registered (the @register decorator ran)
        from bouncers import KINDS
        if KINDS.get(kind) is not cls:
            continue
        manifest = dict(getattr(cls, "PROTEK_MANIFEST", {}) or {})
        manifest.setdefault("kind", kind)
        manifest["path"] = str(path)
        MANIFESTS[kind] = manifest
        log.info("plugin loaded: kind=%s path=%s", kind, path)


def load_all() -> dict[str, dict[str, Any]]:
    """Scan the plugin dir, import every .py file. Idempotent across calls
    (re-importing a module re-runs @register, which is a no-op on the same
    class instance)."""
    d = plugin_dir()
    if not d.exists():
        return MANIFESTS
    for p in sorted(d.glob("*.py")):
        if p.name.startswith("_"):
            continue
        _load_one(p)
    return MANIFESTS


def list_loaded() -> list[dict[str, Any]]:
    """For the UI — flat list of manifests + their config requirements."""
    out = []
    for kind, m in sorted(MANIFESTS.items()):
        out.append({
            "kind": kind,
            "path": m.get("path", ""),
            "author": m.get("author", ""),
            "version": m.get("version", ""),
            "summary": m.get("summary", ""),
            "required": list(m.get("required", []) or []),
        })
    return out
