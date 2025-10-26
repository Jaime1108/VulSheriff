"""API key persistence and setup helpers."""

from __future__ import annotations

import json
import os
from getpass import getpass
from pathlib import Path
from typing import Optional

from flask import Flask

from .config import API_KEY_ENV_VAR
from .gemini_service import ensure_gemini_client


def get_config_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "VulnSherif"
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "vulnsherif"


def config_path() -> Path:
    return get_config_dir() / "config.json"


def load_saved_api_key() -> str:
    try:
        cfg_file = config_path()
        if cfg_file.is_file():
            data = json.loads(cfg_file.read_text(encoding="utf-8"))
            key = data.get(API_KEY_ENV_VAR, "")
            if key:
                return key
    except Exception:
        pass
    return ""


def save_api_key_secure(key: str, logger) -> None:
    try:
        cfg_dir = get_config_dir()
        cfg_dir.mkdir(parents=True, exist_ok=True)
        cfg = {API_KEY_ENV_VAR: key}
        path = cfg_dir / "config.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to save API key: %s", exc)


def ensure_api_key_interactive(app: Flask, logger) -> str:
    key = app.config.get(API_KEY_ENV_VAR) or os.getenv(API_KEY_ENV_VAR, "")
    if key:
        app.config[API_KEY_ENV_VAR] = key
        ensure_gemini_client(key)
        return key

    key = load_saved_api_key()
    if key:
        app.config[API_KEY_ENV_VAR] = key
        os.environ[API_KEY_ENV_VAR] = key
        logger.info("Loaded GEMINI_API_KEY from user config")
        ensure_gemini_client(key)
        return key

    try:
        print("Gemini API key not found.")
        key = getpass("Enter your Gemini API key (input hidden): ").strip()
    except Exception:
        key = input("Enter your Gemini API key: ").strip()
    if not key:
        raise RuntimeError("No API key provided")
    app.config[API_KEY_ENV_VAR] = key
    os.environ[API_KEY_ENV_VAR] = key
    save_api_key_secure(key, logger)
    logger.info("Saved API key to user config directory")
    ensure_gemini_client(key)
    return key
