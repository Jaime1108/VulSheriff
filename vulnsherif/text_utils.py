"""Text processing helpers used across the application."""

from __future__ import annotations

import json
import re
from typing import Any


def coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        try:
            return json.dumps(value, indent=2)
        except Exception:
            return str(value)
    return str(value).strip()


def sanitize_text_for_prompt(text: str) -> str:
    sanitized = []
    for ch in text:
        code = ord(ch)
        if code < 32 and ch not in ("\t", "\n", "\r"):
            continue
        sanitized.append(ch)
    cleaned = "".join(sanitized)
    cleaned = re.sub(r"\s+\Z", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def truncate_words(text: str, max_words: int = 40) -> str:
    if not text:
        return ""
    words = text.split()
    if len(words) <= max_words:
        return text
    return " ".join(words[:max_words]) + "..."


def clamp_characters(text: str, max_chars: int) -> str:
    if not text:
        return ""
    normalized = " ".join(text.split()).strip()
    if len(normalized) <= max_chars:
        return normalized
    truncated = normalized[:max_chars].rstrip()
    if len(normalized) > max_chars:
        last_space = truncated.rfind(" ")
        if last_space > 0:
            truncated = truncated[:last_space].rstrip()
    return truncated or normalized[:max_chars].rstrip()


def format_bytes(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024.0:
            return f"{num:.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PB"


__all__ = [
    "clamp_characters",
    "coerce_text",
    "format_bytes",
    "sanitize_text_for_prompt",
    "truncate_words",
]
