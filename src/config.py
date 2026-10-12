"""Run configuration: non-secret settings from config/settings.json, secrets from .env.

Paths in settings.json are relative to the repository root so the project runs
from any working directory after a fresh clone.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = ROOT / "config" / "settings.json"
SECRET_KEYS = ("OLLAMA_API_KEY", "TAVILY_API_KEY")


def path(rel: str) -> Path:
    """Resolve a repo-relative path from settings.json."""
    return ROOT / rel


def load_settings(settings_path: Path = SETTINGS_PATH, overrides: dict | None = None) -> dict:
    """Load settings.json, apply .env model overrides, then caller overrides (e.g. --fail flags)."""
    load_dotenv(ROOT / ".env")
    s = json.loads(settings_path.read_text(encoding="utf-8"))
    if os.getenv("OLLAMA_MODEL"):
        s["model"]["name"] = os.environ["OLLAMA_MODEL"]
    for section, values in (overrides or {}).items():
        s[section].update(values)
    return s


def secret(name: str) -> str | None:
    """Read an API key. Returns None when unset so callers can fail with a clear message."""
    load_dotenv(ROOT / ".env")
    return os.getenv(name) or None


def redacted(settings: dict) -> dict:
    """Settings safe to save in a run folder (settings never hold secrets, but guard anyway)."""
    s = copy.deepcopy(settings)
    blob = json.dumps(s)
    for key in SECRET_KEYS:
        val = os.getenv(key)
        if val and val in blob:
            raise ValueError(f"{key} value found in settings; secrets belong in .env only")
    return s
