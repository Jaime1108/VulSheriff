"""File collection and preprocessing helpers."""

from __future__ import annotations

import hashlib
import os
import random
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from .config import (
    AGGREGATE_CONTENT_PREVIEW_CHARS,
    COMMENT_STRIPPING_ENABLED,
    CRITICAL_KEYWORDS,
    DEFAULT_EXTS,
    DEFAULT_IGNORE_DIRS,
    EXTENSION_WEIGHTS,
    KEYWORD_WEIGHT,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    OVERFLOW_SUMMARY_LIMIT,
    OVERFLOW_SUMMARY_LINES,
    PRIMARY_SELECTION_RATIO,
    SIZE_NORMALIZER,
)
from .text_utils import format_bytes, sanitize_text_for_prompt


RNG = random.Random()


def is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in DEFAULT_EXTS


def smart_truncate(raw: bytes, limit: int) -> Tuple[bytes, bool]:
    if len(raw) <= limit:
        return raw, False
    cutoff = raw[:limit]
    last_newline = cutoff.rfind(b"\n")
    if last_newline == -1 or last_newline < limit * 0.5:
        return cutoff, True
    return cutoff[:last_newline], True


def strip_comments(text: str, extension: str) -> str:
    if not COMMENT_STRIPPING_ENABLED:
        return text
    if extension in {".py", ".rb"}:
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            comment_idx = line.find("#")
            if comment_idx != -1:
                line = line[:comment_idx]
            lines.append(line)
        return "\n".join(lines)
    if extension in {".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".cpp", ".cs", ".go", ".php"}:
        import re

        text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        return text
    if extension in {".html", ".xml"}:
        return text.replace("<!--", "").replace("-->", "")
    return text


def score_candidate(path: str, size: int) -> float:
    _, ext = os.path.splitext(path.lower())
    base_weight = EXTENSION_WEIGHTS.get(ext, 1.0)
    keyword_bonus = 0.0
    parts = path.lower().split("/")
    for keyword in CRITICAL_KEYWORDS:
        if any(keyword in part for part in parts):
            keyword_bonus += KEYWORD_WEIGHT
    size_factor = min(1.0, size / SIZE_NORMALIZER)
    return base_weight + keyword_bonus + size_factor


def summarize_duplicate(original_path: str) -> str:
    return f"[duplicate of {original_path}]"


def find_salient_lines(text: str, max_items: int = 5) -> List[str]:
    highlights: List[str] = []
    if not text:
        return highlights
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped:
            continue
        if any(keyword in lower for keyword in ("todo", "fixme", "security", "password", "secret", "token")):
            highlights.append(stripped[:120])
        elif any(token in lower for token in ("select ", "insert ", "update ", "delete ", "create table", "drop table")):
            highlights.append(stripped[:120])
        elif "http" in stripped or "https" in stripped:
            highlights.append(stripped[:120])
        if len(highlights) >= max_items:
            break
    return highlights


def assign_windows(files: List[Dict[str, Any]], window_size: int = 20) -> None:
    if not files or window_size <= 0:
        return
    for idx, item in enumerate(files):
        window = idx // window_size + 1
        item.setdefault("metadata", {})["window"] = window


def collect_files(
    root_dir: str,
    include_exts=DEFAULT_EXTS,
    ignore_dirs=DEFAULT_IGNORE_DIRS,
    max_files: int = MAX_FILES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> Tuple[List[Dict], int, int]:
    candidates: List[Dict[str, Any]] = []
    digests: Dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs and not d.startswith(".")]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root_dir).replace("\\", "/")
            if not is_text_file(fpath):
                continue
            try:
                full_size = os.path.getsize(fpath)
            except OSError:
                full_size = 0

            try:
                with open(fpath, "rb") as f:
                    raw = f.read(max_file_bytes + 4096)
            except Exception:
                continue

            snippet_bytes, truncated = smart_truncate(raw, max_file_bytes)
            try:
                text = snippet_bytes.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = snippet_bytes.decode("latin-1")
                except Exception:
                    continue

            _, ext = os.path.splitext(rel)
            stripped_comments = strip_comments(text, ext)
            stripped = sanitize_text_for_prompt(stripped_comments)
            encoded = stripped.encode("utf-8", errors="ignore")

            if not encoded:
                if truncated:
                    stripped = "[content omitted: file contained only comments]"
                    encoded = stripped.encode("utf-8")
                else:
                    continue

            content_hash = hashlib.sha256(encoded).hexdigest()
            duplicate_of = digests.get(content_hash)
            if duplicate_of is None and encoded:
                digests[content_hash] = rel

            metadata = {
                "original_path": rel,
                "original_size": full_size or len(raw),
                "truncated": truncated or (full_size and full_size > len(snippet_bytes)),
                "digest": content_hash[:12],
                "comments_stripped": stripped_comments != text,
            }
            if metadata["truncated"]:
                metadata["truncate_notice"] = f"...TRUNCATED (source ~{len(raw)} bytes)"

            candidate = {
                "path": rel,
                "size": len(encoded),
                "truncated": metadata["truncated"],
                "text": stripped,
                "score": score_candidate(rel, len(encoded)),
                "duplicate_of": duplicate_of,
                "metadata": metadata,
            }
            candidates.append(candidate)

    if not candidates:
        return [], 0, 0

    unique_candidates = [c for c in candidates if not c["duplicate_of"]]
    unique_candidates.sort(key=lambda c: c["score"], reverse=True)

    max_primary_files = max(1, int(max_files * PRIMARY_SELECTION_RATIO))
    max_primary_bytes = max(1, int(max_total_bytes * PRIMARY_SELECTION_RATIO))

    selected: List[Dict[str, Any]] = []
    used_files = 0
    used_bytes = 0

    def try_add(candidate: Dict[str, Any]) -> None:
        nonlocal used_files, used_bytes
        if used_files >= max_files:
            return
        candidate_size = max(1, candidate["size"])
        if used_bytes + candidate_size > max_total_bytes:
            return
        selected.append(candidate)
        used_files += 1
        used_bytes += candidate_size

    primary_bytes_used = 0

    for candidate in unique_candidates[:max_primary_files]:
        candidate_size = max(1, candidate["size"])
        if primary_bytes_used + candidate_size > max_primary_bytes and used_files > 0:
            continue
        try_add(candidate)
        primary_bytes_used += candidate_size

    remainder = unique_candidates[max_primary_files:]
    if remainder:
        RNG.shuffle(remainder)
        for candidate in remainder:
            try_add(candidate)
            if used_bytes >= max_total_bytes:
                break

    selected_paths = {c["path"] for c in selected}

    duplicate_notes = []
    for dup in candidates:
        if dup["duplicate_of"] and dup["duplicate_of"] in selected_paths and used_files < max_files:
            note_text = summarize_duplicate(dup["duplicate_of"])
            note_size = len(note_text.encode("utf-8"))
            if used_bytes + note_size > max_total_bytes:
                continue
            duplicate_notes.append(
                {
                    "path": dup["path"],
                    "size": note_size,
                    "truncated": False,
                    "text": note_text,
                    "score": dup["score"] * 0.5,
                    "duplicate_of": dup["duplicate_of"],
                    "metadata": {**dup["metadata"], "summary_only": True},
                }
            )
            used_files += 1
            used_bytes += note_size

    selected.extend(duplicate_notes)
    selected.sort(key=lambda c: c["score"], reverse=True)
    assign_windows(selected)

    return selected, used_files, used_bytes


def format_files_for_prompt(files: List[Dict]) -> str:
    if not files:
        return "No code files provided. Analyze based on user context only."
    parts = [
        "You are given a subset of files from a website project.",
        "Each file is prefixed by '--- file: <path> (<size>)'.",
        "Truncated files end with '...TRUNCATED'.",
        "Review all content holistically.",
        "",
    ]
    current_window = None
    for f in files:
        meta = f.get("metadata") or {}
        window_idx = meta.get("window")
        if window_idx and window_idx != current_window:
            parts.append(f"## Window {window_idx}")
            parts.append("")
            current_window = window_idx
        header = f"--- file: {f['path']} ({format_bytes(f['size'])})"
        parts.append(header)
        info_lines = []
        if meta.get("comments_stripped"):
            info_lines.append("[comments removed for brevity]")
        if meta.get("truncate_notice"):
            info_lines.append(meta["truncate_notice"])
        if f.get("duplicate_of"):
            info_lines.append(summarize_duplicate(f["duplicate_of"]))
        if info_lines:
            parts.extend(info_lines)
        body = f.get("text", "")
        if meta.get("summary_only"):
            parts.append(body)
        elif body and not f.get("duplicate_of"):
            snippet = body.rstrip()
            if f.get("truncated"):
                snippet += "\n...TRUNCATED"
            parts.append("```")
            parts.append(snippet)
            parts.append("```")
        parts.append("")
    return "\n".join(parts)


def safe_extract_zip(zip_file: zipfile.ZipFile, dest_dir: str) -> List[str]:
    extracted_paths = []
    base = os.path.abspath(dest_dir)
    for member in zip_file.infolist():
        if member.filename.endswith("/"):
            continue
        member_path = os.path.abspath(os.path.join(dest_dir, member.filename))
        if not member_path.startswith(base + os.sep) and member_path != base:
            raise ValueError(f"Blocked path traversal attempt: {member.filename}")
        os.makedirs(os.path.dirname(member_path), exist_ok=True)
        with zip_file.open(member) as src, open(member_path, "wb") as dst:
            dst.write(src.read())
        extracted_paths.append(member_path)
    return extracted_paths


__all__ = [
    "AGGREGATE_CONTENT_PREVIEW_CHARS",
    "collect_files",
    "find_salient_lines",
    "format_files_for_prompt",
    "safe_extract_zip",
    "RNG",
    "summarize_duplicate",
]
