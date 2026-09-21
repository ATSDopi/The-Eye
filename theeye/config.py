"""Config: optional API keys loaded from .env (never hardcoded, never committed)."""

from __future__ import annotations

import os
from pathlib import Path

ENV_PATH = Path(__file__).parent.parent / ".env"

_loaded = False


def _load_env():
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


def get(key: str) -> str | None:
    _load_env()
    return os.environ.get(key) or None


def intelx_key() -> str | None:
    return get("INTELX_KEY")
