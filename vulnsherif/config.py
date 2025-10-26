"""Application configuration and global constants for VulnSherif."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


# Ensure environment variables are loaded from common locations
load_dotenv()
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")


FORCED_MODEL = "gemini-2.5-pro"
API_KEY_ENV_VAR = "GEMINI_API_KEY"
DEFAULT_TEMPERATURE = 0.2
MAX_TOTAL_BYTES = 2_000_000
MAX_FILE_BYTES = 100_000
MAX_FILES = 120
PRIMARY_SELECTION_RATIO = 0.75
COMMENT_STRIPPING_ENABLED = True
OVERFLOW_SUMMARY_LIMIT = 10
OVERFLOW_SUMMARY_LINES = 4
MAX_PER_FILE_ANALYSES = 30
RATE_LIMIT_MIN_DELAY = 3.2
PER_FILE_MAX_RETRIES = 3
AGGREGATE_CONTENT_PREVIEW_CHARS = 2000
EXECUTOR_MAX_WORKERS = int(os.getenv("VULNSHERIF_MAX_WORKERS", "2"))

EXTENSION_WEIGHTS = {
    ".php": 1.4,
    ".py": 1.35,
    ".js": 1.3,
    ".ts": 1.3,
    ".jsx": 1.3,
    ".tsx": 1.3,
    ".rb": 1.25,
    ".go": 1.25,
    ".java": 1.2,
    ".cs": 1.2,
    ".rs": 1.2,
    ".kt": 1.2,
    ".sql": 1.35,
    ".yml": 1.2,
    ".yaml": 1.2,
    ".env": 1.3,
    ".ini": 1.2,
    ".json": 1.1,
    ".html": 1.15,
    ".htm": 1.15,
    ".vue": 1.15,
}

CRITICAL_KEYWORDS = [
    "auth",
    "login",
    "signup",
    "register",
    "token",
    "secret",
    "password",
    "config",
    "env",
    "admin",
    "session",
    "payment",
    "checkout",
    "upload",
    "storage",
    "db",
]

KEYWORD_WEIGHT = 0.25
SIZE_NORMALIZER = 50_000

DEFAULT_EXTS = {
    ".py",
    ".php",
    ".rb",
    ".go",
    ".java",
    ".cs",
    ".rs",
    ".kt",
    ".mjs",
    ".cjs",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".html",
    ".htm",
    ".ejs",
    ".jinja",
    ".jinja2",
    ".twig",
    ".liquid",
    ".css",
    ".scss",
    ".sass",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".env",
    ".conf",
    ".sql",
    ".xml",
}

DEFAULT_IGNORE_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
}
