import os
import io
import json
import time
import uuid
import zipfile
from typing import List, Tuple, Dict
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# ----------------------------
# CONSTANTS
# ----------------------------
MAX_TOTAL_BYTES = 2_000_000
MAX_FILE_BYTES = 100_000
MAX_FILES = 120

DEFAULT_EXTS = {
    ".py", ".php", ".rb", ".go", ".java", ".cs", ".rs", ".kt", ".mjs", ".cjs",
    ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".html", ".htm", ".ejs", ".jinja", ".jinja2", ".twig", ".liquid",
    ".css", ".scss", ".sass",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".env", ".conf",
    ".sql", ".xml"
}

DEFAULT_IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "coverage", "__pycache__",
    ".next", ".nuxt", ".cache", ".venv", "venv", "env", ".idea", ".vscode"
}
def is_text_file(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in DEFAULT_EXTS
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

# ----------------------------
# HELPERS
# ----------------------------
def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"

def collect_files(root_dir: str) -> Tuple[List[Dict], int, int]:
    """Collect and read text files from extracted ZIP."""
    selected, total_bytes, file_count = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS and not d.startswith(".")]
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root_dir).replace("\\", "/")
            if not is_text_file(fpath):
                continue
            if file_count >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
                break
            try:
                with open(fpath, "rb") as f:
                    raw = f.read(MAX_FILE_BYTES + 1)
            except Exception:
                continue
            truncated = len(raw) > MAX_FILE_BYTES
            content = raw[:MAX_FILE_BYTES]
            try:
                text = content.decode("utf-8", errors="ignore")
            except Exception:
                continue
            selected.append({
                "path": rel,
                "size": len(content),
                "truncated": truncated,
                "text": text
            })
            file_count += 1
            total_bytes += len(content)
        if file_count >= MAX_FILES or total_bytes >= MAX_TOTAL_BYTES:
            break
    return selected, file_count, total_bytes

def format_files_for_prompt(files: List[Dict]) -> str:
    """Format the collected files into a text block for the AI model."""
    if not files:
        return "No code files provided."
    parts = [
        "You are given a subset of files from a project.",
        "Each file is prefixed by '--- file: <path> (<size>)'.",
        ""
    ]
    for f in files:
        header = f"--- file: {f['path']} ({format_bytes(f['size'])})"
        body = f["text"]
        if f["truncated"]:
            body += "\n...TRUNCATED"
        parts.append(header)
        parts.append("```")
        parts.append(body)
        parts.append("```")
        parts.append("")
    return "\n".join(parts)