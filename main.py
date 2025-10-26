import os
import io
import json
import time
import uuid
import zipfile
import shutil
import tempfile
import logging
import hashlib
import random
import re
import signal
from collections import defaultdict
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import sys
from dotenv import load_dotenv
from pathlib import Path
from getpass import getpass

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
except ImportError:  # pragma: no cover - handled at runtime with helpful message
    genai = None
    google_exceptions = None


# ----------------------------
# FLASK APP CONFIG
# ----------------------------
# Load environment variables from a local .env file if present
# Load default search locations (CWD)
load_dotenv()
# Also explicitly load .env located next to this file (script directory)
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB upload cap
app.config["GEMINI_API_KEY"] = os.environ.get("GEMINI_API_KEY", "")


# ----------------------------
# CONSTANTS
# ----------------------------
# Force a specific model (handled purely backend)
FORCED_MODEL = "gemini-2.5-pro"
API_KEY_ENV_VAR = "GEMINI_API_KEY"
DEFAULT_TEMPERATURE = 0.2
MAX_TOTAL_BYTES = 2_000_000
MAX_FILE_BYTES = 100_000
MAX_FILES = 120
PRIMARY_SELECTION_RATIO = 0.75  # 75% of budget for highest scoring files
COMMENT_STRIPPING_ENABLED = True
OVERFLOW_SUMMARY_LIMIT = 10
OVERFLOW_SUMMARY_LINES = 4
MAX_PER_FILE_ANALYSES = 30
RATE_LIMIT_MIN_DELAY = 3.2  # seconds between free model calls
PER_FILE_MAX_RETRIES = 3

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
SIZE_NORMALIZER = 50_000  # bytes
RNG = random.Random()

executor = ThreadPoolExecutor(max_workers=max(1, EXECUTOR_MAX_WORKERS))
job_store: Dict[str, Dict[str, Any]] = {}
progress_lock = Lock()
rate_limit_lock = Lock()
last_model_call = {"timestamp": 0.0}

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


# ----------------------------
# HELPERS
# ----------------------------
def setup_logger():
    level_name = os.getenv("VULNSHERIF_LOG_LEVEL") or ("DEBUG" if os.getenv("VULNSHERIF_DEBUG") else "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    return logging.getLogger("vulnsherif")


logger = setup_logger()
if app.config.get(API_KEY_ENV_VAR):
    logger.info("Detected GEMINI_API_KEY from environment/.env")
else:
    logger.warning("GEMINI_API_KEY not set; will prompt on first run and store securely in user config.")


def _shutdown_handler(signum, frame):
    logger.warning(f"Received shutdown signal ({signum}); cancelling pending work and exiting.")
    try:
        executor.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass
    for thread in list(getattr(executor, "_threads", [])):
        try:
            thread.daemon = True
        except Exception:
            pass
    os._exit(0)


def _register_shutdown_signals():
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is None:
            continue
        try:
            signal.signal(sig, _shutdown_handler)
        except (AttributeError, ValueError):
            # AttributeError: signal missing on platform (e.g., SIGTERM on Windows)
            # ValueError: signal registration attempted from non-main thread (shouldn't happen here)
            continue


_register_shutdown_signals()

_configured_gemini_key: Optional[str] = None


def ensure_gemini_client(api_key: str) -> None:
    """Configure the Gemini SDK once per API key."""
    global _configured_gemini_key
    if genai is None:
        raise RuntimeError(
            "google-generativeai is not installed. "
            "Install dependencies (`pip install -r requirements.txt`) and try again."
        )
    if not api_key:
        raise RuntimeError("Missing Gemini API key.")
    if _configured_gemini_key == api_key:
        return
    genai.configure(api_key=api_key)
    _configured_gemini_key = api_key


# ----------------------------
# FIRST-RUN API KEY SETUP
# ----------------------------
def get_config_dir() -> Path:
    """Return a per-user config dir to store secrets (not in repo)."""
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "VulnSherif"
    # POSIX
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


def save_api_key_secure(key: str) -> None:
    try:
        cfg_dir = get_config_dir()
        cfg_dir.mkdir(parents=True, exist_ok=True)
        cfg = {API_KEY_ENV_VAR: key}
        p = cfg_dir / "config.json"
        p.write_text(json.dumps(cfg), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to save API key: {e}")


def ensure_api_key_interactive():
    """Ensure we have an API key: env -> saved config -> interactive prompt."""
    # 1) Env/app config
    key = app.config.get(API_KEY_ENV_VAR) or os.getenv(API_KEY_ENV_VAR, "")
    if key:
        app.config[API_KEY_ENV_VAR] = key
        ensure_gemini_client(key)
        return key
    # 2) Saved config
    key = load_saved_api_key()
    if key:
        app.config[API_KEY_ENV_VAR] = key
        os.environ[API_KEY_ENV_VAR] = key
        logger.info("Loaded GEMINI_API_KEY from user config")
        ensure_gemini_client(key)
        return key
    # 3) Prompt user once
    try:
        print("Gemini API key not found.")
        key = getpass("Enter your Gemini API key (input hidden): ").strip()
    except Exception:
        key = input("Enter your Gemini API key: ").strip()
    if not key:
        raise RuntimeError("No API key provided")
    app.config[API_KEY_ENV_VAR] = key
    os.environ[API_KEY_ENV_VAR] = key
    save_api_key_secure(key)
    logger.info("Saved API key to user config directory")
    ensure_gemini_client(key)
    return key


def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def _strip_comment_lines(text: str, markers: List[str]) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if any(stripped.startswith(marker) for marker in markers):
            continue
        lines.append(line)
    return "\n".join(lines)


def strip_comments(text: str, ext: str) -> str:
    if not COMMENT_STRIPPING_ENABLED:
        return text
    ext = (ext or "").lower()
    if ext in {".py", ".rb", ".sh", ".env", ".ini", ".conf"}:
        return _strip_comment_lines(text, ["#", ";"])
    if ext in {".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".css", ".scss", ".sass", ".c", ".cpp"}:
        stripped = _strip_comment_lines(text, ["//"])
        try:
            import re

            stripped = re.sub(r"/\*[\s\S]*?\*/", "", stripped)
        except Exception:
            pass
        return stripped
    if ext in {".html", ".htm", ".xml", ".vue"}:
        try:
            import re

            return re.sub(r"<!--[\s\S]*?-->", "", text)
        except Exception:
            return text
    return text


def smart_truncate(raw: bytes, limit: int) -> Tuple[bytes, bool]:
    if len(raw) <= limit:
        return raw, False
    preview = raw[:limit]
    cut = preview.rfind(b"\n", int(limit * 0.4))
    if cut != -1 and cut > int(limit * 0.2):
        preview = preview[:cut]
    return preview, True


def score_candidate(path: str, size: int) -> float:
    _, ext = os.path.splitext(path)
    ext = ext.lower()
    score = EXTENSION_WEIGHTS.get(ext, 1.0)
    lowered = path.lower()
    for keyword in CRITICAL_KEYWORDS:
        if keyword in lowered:
            score += KEYWORD_WEIGHT
    score += min(size / SIZE_NORMALIZER, 1.0)
    return score


def sanitize_text_for_prompt(text: str) -> str:
    if not text:
        return text
    return text.replace("\r\n", "\n").replace("\r", "\n")


def summarize_duplicate(original_path: str) -> str:
    return f"[duplicate content omitted; see {original_path}]"


def summarize_structure(text: str, max_items: int = 6) -> List[str]:
    highlights = []
    if not text:
        return highlights
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith(("function ", "def ", "class ", "interface ", "trait ", "enum ", "async ", "public ", "private ", "protected ", "var ", "let ", "const ", "$", "import ", "export ")):
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


def wait_for_rate_limit(min_delay: float = RATE_LIMIT_MIN_DELAY) -> None:
    if min_delay <= 0:
        return
    with rate_limit_lock:
        now = time.time()
        elapsed = now - last_model_call["timestamp"]
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        last_model_call["timestamp"] = time.time()


def init_job(req_id: str) -> None:
    with progress_lock:
        job_store[req_id] = {
            "status": "running",
            "progress": [],
            "result": None,
            "error": None,
            "started_at": time.time(),
        }


def update_job_progress(req_id: str, stage: str, detail: Optional[str] = None, state: str = "running") -> None:
    with progress_lock:
        entry = job_store.get(req_id)
        if not entry:
            return
        if state in {"running", "queued", "waiting", "completed", "failed"}:
            entry["status"] = state
        entry["progress"].append({
            "timestamp": time.time(),
            "stage": stage,
            "detail": detail or "",
            "state": state,
        })


def complete_job(req_id: str, result: Dict[str, Any]) -> None:
    with progress_lock:
        entry = job_store.get(req_id)
        if not entry:
            return
        entry["status"] = "completed"
        entry["result"] = result
        entry["completed_at"] = time.time()


def fail_job(req_id: str, message: str) -> None:
    with progress_lock:
        entry = job_store.setdefault(req_id, {})
        entry["status"] = "failed"
        entry["error"] = message
        entry["completed_at"] = time.time()


def get_job(req_id: str) -> Optional[Dict[str, Any]]:
    with progress_lock:
        data = job_store.get(req_id)
        if not data:
            return None
        return json.loads(json.dumps(data, default=str))


SEVERITY_LABELS = ["Critical", "High", "Medium", "Low"]
SEVERITY_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    "p0": "Critical",
    "high": "High",
    "p1": "High",
    "medium": "Medium",
    "med": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "p3": "Low",
}


def normalize_severity(value: Any) -> str:
    if not value:
        return "Medium"
    norm = str(value).strip().lower()
    if norm in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[norm]
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or "Medium"
    return "Medium"


def coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        try:
            return json.dumps(value, indent=2)
        except Exception:
            return str(value)
    return str(value).strip()


def sanitize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    files = raw.get("files") or []
    if isinstance(files, (str, bytes)):
        files = [files]
    clean_files = []
    for item in files:
        if item is None:
            continue
        clean_files.append(str(item))

    cve_id = raw.get("cve_id") or raw.get("cve")
    cvss = raw.get("cvss_score") or raw.get("cvss")

    finding = {
        "title": coerce_text(raw.get("title") or "Untitled Finding"),
        "severity": normalize_severity(raw.get("severity")),
        "category": coerce_text(raw.get("category")),
        "files": clean_files,
        "cve_id": coerce_text(cve_id),
        "cvss_score": coerce_text(cvss),
        "description": coerce_text(raw.get("description")),
        "evidence": coerce_text(raw.get("evidence")),
        "remediation": coerce_text(raw.get("remediation")),
    }
    return finding


def build_report(raw_payload: Any, fallback_summary: str = "") -> Optional[Dict[str, Any]]:
    if not isinstance(raw_payload, dict):
        return None
    raw_findings = raw_payload.get("findings") or []
    findings: List[Dict[str, Any]] = []
    if isinstance(raw_findings, list):
        for item in raw_findings:
            sanitized = sanitize_finding(item)
            if sanitized:
                findings.append(sanitized)

    def sort_key(item: Dict[str, Any]) -> tuple:
        sev = normalize_severity(item.get("severity"))
        try:
            rank = SEVERITY_LABELS.index(sev)
        except ValueError:
            rank = len(SEVERITY_LABELS)
        return (rank, item.get("title", "").lower())

    findings.sort(key=sort_key)

    summary = coerce_text(raw_payload.get("summary") or fallback_summary)
    return {"summary": summary, "findings": findings}


def build_frontend_payload(job_result: Dict[str, Any]) -> Dict[str, Any]:
    report = job_result.get("report") or {}
    raw_findings = report.get("findings") or []
    prepared_findings: List[Dict[str, str]] = []
    for raw in raw_findings:
        severity = normalize_severity(raw.get("severity"))
        prepared_findings.append({
            "title": coerce_text(raw.get("title") or "Untitled Finding"),
            "severity": severity,
            "description": coerce_text(raw.get("description") or "No description provided."),
            "suggestion": coerce_text(
                raw.get("remediation")
                or raw.get("suggestion")
                or "No remediation guidance provided."
            ),
        })
    if not prepared_findings:
        summary_text = coerce_text(report.get("summary")) or coerce_text(job_result.get("status_message"))
        prepared_findings.append({
            "title": "No Vulnerabilities Reported",
            "severity": "Low",
            "description": summary_text or "The analysis completed without returning structured findings.",
            "suggestion": "If you expected findings, consider rerunning the scan with additional context or files.",
        })
    return {
        "findings": prepared_findings,
        "summary": coerce_text(report.get("summary")),
        "scan_meta": job_result.get("scan_meta"),
        "severity_counts": job_result.get("severity_counts"),
        "status_message": job_result.get("status_message"),
        "raw_report": report,
    }


def build_frontend_error_payload(message: str, severity: str = "High") -> Dict[str, Any]:
    safe_message = coerce_text(message) or "Analysis failed unexpectedly."
    return {
        "findings": [{
            "title": "Analysis Failed",
            "severity": normalize_severity(severity),
            "description": safe_message,
            "suggestion": "Please try again later or adjust your input files and resubmit.",
        }],
        "summary": "",
        "scan_meta": None,
        "severity_counts": None,
        "status_message": safe_message,
        "raw_report": None,
    }


def build_scan_meta(req_id: str,
                    files: List[Dict[str, Any]],
                    elapsed_seconds: float,
                    model: str,
                    temperature: float,
                    packaged_bytes: int,
                    notes: str,
                    prompt_only: bool) -> Dict[str, Any]:
    total_bytes = sum(f.get("size", 0) for f in files)
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    return {
        "request_id": req_id,
        "timestamp": timestamp,
        "files_included": len(files),
        "max_files": MAX_FILES,
        "text_bytes": total_bytes,
        "text_size": format_bytes(total_bytes),
        "packaged_bytes": packaged_bytes,
        "model_used": model,
        "temperature": temperature,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "elapsed_human": f"{elapsed_seconds:.1f}s",
        "prompt_only": bool(prompt_only),
        "notes_provided": bool(notes.strip()),
    }


def call_model_for_file(api_key: str,
                        model: str,
                        file_item: Dict[str, Any],
                        temperature: float,
                        req_id: str,
                        timeout: int = 120,
                        progress_cb=None) -> Optional[Dict[str, Any]]:
    system_prompt = build_per_file_system_prompt()
    file_text = file_item.get("text") or ""
    user_content = (
        f"File path: {file_item.get('path')}\n"
        f"Truncated: {file_item.get('truncated')}\n"
        "File content:\n"
        "```\n"
        f"{file_text}\n"
        "```\n"
    )
    for attempt in range(1, PER_FILE_MAX_RETRIES + 1):
        if progress_cb:
            progress_cb(f"file:{file_item.get('path')}", f"Attempt {attempt}")
        wait_for_rate_limit()
        try:
            content = call_gemini_generate(
                api_key=api_key,
                model=model,
                system_prompt=system_prompt,
                user_content=user_content,
                temperature=temperature,
                timeout=timeout,
                max_output_tokens=2048,
            )
            parsed = try_extract_json_block(content or "")
            if not parsed:
                snippet = (content or "").strip()
                logger.warning(
                    f"[{req_id}] per-file JSON missing for {file_item.get('path')}. excerpt={snippet[:200]!r}"
                )
                if progress_cb:
                    progress_cb(f"file:{file_item.get('path')}", "No structured JSON", state="warning")
                return None
            parsed.setdefault("file_path", file_item.get("path"))
            if progress_cb:
                progress_cb(f"file:{file_item.get('path')}", "Completed", state="success")
            return parsed
        except Exception as exc:
            if google_exceptions and isinstance(exc, google_exceptions.ResourceExhausted):
                wait_seconds = 8.0
                retry_delay = getattr(exc, "retry_delay", None)
                if retry_delay:
                    try:
                        wait_seconds = max(wait_seconds, float(retry_delay.total_seconds()))  # type: ignore[arg-type]
                    except Exception:
                        try:
                            wait_seconds = max(wait_seconds, float(retry_delay))
                        except Exception:
                            pass
                if progress_cb:
                    progress_cb(
                        f"file:{file_item.get('path')}",
                        f"Rate limited; retrying in {wait_seconds:.0f}s",
                        state="waiting",
                    )
                logger.warning(f"[{req_id}] rate limit on {file_item.get('path')} attempt {attempt}: {exc}")
                time.sleep(wait_seconds)
                continue
            if isinstance(exc, RuntimeError):
                logger.warning(f"[{req_id}] per-file analysis failed for {file_item.get('path')}: {exc}")
                if progress_cb:
                    progress_cb(f"file:{file_item.get('path')}", "Failed", state="error")
                return None
            if google_exceptions and isinstance(exc, google_exceptions.GoogleAPIError):
                logger.warning(f"[{req_id}] Gemini API error for {file_item.get('path')}: {exc}")
                if progress_cb:
                    progress_cb(f"file:{file_item.get('path')}", "API error", state="error")
                return None
            logger.warning(f"[{req_id}] per-file analysis failed for {file_item.get('path')}: {exc}")
            if progress_cb:
                progress_cb(f"file:{file_item.get('path')}", "Failed", state="error")
            return None
    logger.warning(f"[{req_id}] per-file retries exhausted for {file_item.get('path')}")
    if progress_cb:
        progress_cb(f"file:{file_item.get('path')}", "Failed after retries", state="error")
    return None


def call_model_for_aggregate(api_key: str,
                             model: str,
                             per_file_results: List[Dict[str, Any]],
                             notes: str,
                             temperature: float,
                             req_id: str,
                             timeout: int = 180,
                             progress_cb=None) -> Optional[Dict[str, Any]]:
    system_prompt = build_final_system_prompt()
    user_payload = build_final_user_payload(per_file_results, notes)
    for attempt in range(1, PER_FILE_MAX_RETRIES + 1):
        try:
            if progress_cb:
                progress_cb("aggregate", f"Synthesizing final report (attempt {attempt})")
            wait_for_rate_limit()
            content = call_gemini_generate(
                api_key=api_key,
                model=model,
                system_prompt=system_prompt,
                user_content=f"Per-file findings:\n```json\n{user_payload}\n```",
                temperature=temperature,
                timeout=timeout,
                max_output_tokens=8192,
            )
            parsed = try_extract_json_block(content or "")
            if not parsed:
                snippet = (content or "").strip()
                logger.error(f"[{req_id}] aggregate JSON missing. excerpt={snippet[:400]!r}")
                if progress_cb:
                    progress_cb("aggregate", "No structured response", state="error")
                return None
            if progress_cb:
                progress_cb("aggregate", "Completed", state="success")
            return parsed
        except Exception as exc:
            if google_exceptions and isinstance(exc, google_exceptions.ResourceExhausted):
                wait_seconds = 10.0
                retry_delay = getattr(exc, "retry_delay", None)
                if retry_delay:
                    try:
                        wait_seconds = max(wait_seconds, float(retry_delay.total_seconds()))  # type: ignore[arg-type]
                    except Exception:
                        try:
                            wait_seconds = max(wait_seconds, float(retry_delay))
                        except Exception:
                            pass
                if attempt < PER_FILE_MAX_RETRIES:
                    if progress_cb:
                        progress_cb("aggregate", f"Rate limited; retrying in {wait_seconds:.0f}s", state="waiting")
                    logger.warning(f"[{req_id}] aggregate rate limit attempt {attempt}: {exc}")
                    time.sleep(wait_seconds)
                    continue
            if isinstance(exc, RuntimeError):
                logger.error(f"[{req_id}] aggregate analysis failed: {exc}")
                if progress_cb:
                    progress_cb("aggregate", f"Failed: {exc}", state="error")
                return None
            if google_exceptions and isinstance(exc, google_exceptions.GoogleAPIError):
                logger.error(f"[{req_id}] aggregate Gemini API error: {exc}")
                if progress_cb:
                    progress_cb("aggregate", f"API error: {exc}", state="error")
                return None
            logger.error(f"[{req_id}] aggregate analysis failed: {exc}")
            if progress_cb:
                progress_cb("aggregate", f"Failed: {exc}", state="error")
            return None
    return None


def perform_analysis_job(req_id: str,
                         api_key: str,
                         zip_path: Optional[str],
                         notes: str,
                         prompt_only: bool,
                         dry_run: bool,
                         debug_mode: bool,
                         temperature: float) -> None:
    start = time.time()
    update_job_progress(req_id, "init", "Preparing analysis inputs")
    tmp_root = tempfile.mkdtemp(prefix="vulnsherif_job_")
    files: List[Dict[str, Any]] = []
    packaged_len = 0
    analyzable_files: List[Dict[str, Any]] = []
    per_file_results: List[Dict[str, Any]] = []
    aggregate_json: Optional[Dict[str, Any]] = None
    try:
        if not api_key:
            raise RuntimeError("Missing Gemini API key.")
        ensure_gemini_client(api_key)
        if zip_path:
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    update_job_progress(req_id, "files", "Extracting ZIP archive")
                    safe_extract_zip(zf, tmp_root)
            except zipfile.BadZipFile as exc:
                raise RuntimeError("Invalid ZIP archive.") from exc
        if zip_path or prompt_only:
            files, count, total = collect_files(tmp_root)
            update_job_progress(req_id, "files", f"Collected {len(files)} files ({format_bytes(total)})")
        else:
            raise RuntimeError("Upload a ZIP or enable prompt-only mode with context.")

        packaged = format_files_for_prompt(files)
        packaged_len = len(packaged.encode("utf-8", errors="ignore"))
        analyzable_files = [
            f for f in files
            if not f.get("summary_only") and not f.get("duplicate_of") and f.get("text")
        ][:MAX_PER_FILE_ANALYSES]

        with progress_lock:
            if req_id in job_store:
                job_store[req_id]["targets"] = len(analyzable_files)

        if dry_run:
            update_job_progress(req_id, "dry_run", "Dry run completed")
            elapsed = time.time() - start
            scan_meta = build_scan_meta(
                req_id=req_id,
                files=files,
                elapsed_seconds=elapsed,
                model=FORCED_MODEL,
                temperature=temperature,
                packaged_bytes=packaged_len,
                notes=notes,
                prompt_only=prompt_only,
            )
            context = {
                "report": None,
                "report_json": None,
                "scan_meta": scan_meta,
                "severity_counts": {label: 0 for label in SEVERITY_LABELS},
                "severity_order": SEVERITY_LABELS,
                "grouped_findings": {label: [] for label in SEVERITY_LABELS},
                "other_findings": [],
                "total_findings": 0,
                "status_message": "Dry run mode: Gemini call skipped before contacting the model.",
                "debug_mode": debug_mode,
            }
            complete_job(req_id, context)
            return

        def progress_hook(stage: str, detail: str = "", state: str = "running") -> None:
            update_job_progress(req_id, stage, detail, state)

        total_targets = len(analyzable_files)
        if total_targets:
            progress_hook("file-progress", f"0/{total_targets} processed")
        completed_count = 0
        for idx, file_item in enumerate(analyzable_files, 1):
            result = call_model_for_file(
                api_key=api_key,
                model=FORCED_MODEL,
                file_item=file_item,
                temperature=temperature,
                req_id=req_id,
                progress_cb=progress_hook,
            )
            if result:
                per_file_results.append(result)
            completed_count += 1
            progress_hook("file-progress", f"{completed_count}/{total_targets} processed")

        analyzed_paths = {item.get("file_path") for item in per_file_results}
        for file_item in files:
            path = file_item.get("path")
            if path in analyzed_paths:
                continue
            per_file_results.append({
                "file_path": path,
                "summary": "Not analyzed directly (token budget); covered via aggregated context.",
                "findings": [],
            })
        if not per_file_results and prompt_only:
            per_file_results.append({
                "file_path": "prompt_only",
                "summary": "No files analyzed; report based on user context.",
                "findings": [],
            })

        update_job_progress(req_id, "aggregate", "Synthesizing report")
        aggregate_json = call_model_for_aggregate(
            api_key=api_key,
            model=FORCED_MODEL,
            per_file_results=per_file_results,
            notes=notes,
            temperature=temperature,
            req_id=req_id,
            progress_cb=progress_hook,
        )
        if not aggregate_json:
            raise RuntimeError("Failed to synthesize aggregate report from per-file analysis.")

        elapsed = time.time() - start
        scan_meta = build_scan_meta(
            req_id=req_id,
            files=files,
            elapsed_seconds=elapsed,
            model=FORCED_MODEL,
            temperature=temperature,
            packaged_bytes=packaged_len,
            notes=notes,
            prompt_only=prompt_only,
        )

        report = build_report(aggregate_json, fallback_summary="")
        status_message = None
        if report is None:
            status_message = "Structured JSON block missing from final model response."
        else:
            if not report.get("summary"):
                report["summary"] = "Summary missing from model response."

        grouped_findings = {label: [] for label in SEVERITY_LABELS}
        other_findings: List[Dict[str, Any]] = []
        if report:
            for finding in report.get("findings", []):
                severity = normalize_severity(finding.get("severity"))
                finding["severity"] = severity
                if severity in grouped_findings:
                    grouped_findings[severity].append(finding)
                else:
                    other_findings.append(finding)
        severity_counts = {label: len(grouped_findings[label]) for label in SEVERITY_LABELS}
        total_findings = sum(severity_counts.values()) + len(other_findings)
        if report and not report.get("findings"):
            status_message = status_message or "Model returned no findings for the selected files."

        context = {
            "report": report,
            "scan_meta": scan_meta,
            "severity_counts": severity_counts,
            "severity_order": SEVERITY_LABELS,
            "grouped_findings": grouped_findings,
            "other_findings": other_findings,
            "total_findings": total_findings,
            "status_message": status_message,
            "debug_mode": debug_mode,
        }
        update_job_progress(req_id, "finalize", "Report ready", state="completed")
        complete_job(req_id, context)
    except Exception as exc:
        logger.exception(f"[{req_id}] analysis job failed: {exc}")
        update_job_progress(req_id, "finalize", str(exc), state="failed")
        fail_job(req_id, str(exc))
    finally:
        try:
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass
        if zip_path:
            try:
                os.unlink(zip_path)
            except Exception:
                pass



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


def collect_files(root_dir: str,
                  include_exts=DEFAULT_EXTS,
                  ignore_dirs=DEFAULT_IGNORE_DIRS,
                  max_files: int = MAX_FILES,
                  max_total_bytes: int = MAX_TOTAL_BYTES,
                  max_file_bytes: int = MAX_FILE_BYTES) -> Tuple[List[Dict], int, int]:
    candidates: List[Dict[str, Any]] = []
    digests: Dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs and not d.startswith('.')]

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
                    # Edge case: file is large but comment-only; keep notice.
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
            duplicate_notes.append({
                "path": dup["path"],
                "size": note_size,
                "truncated": False,
                "text": note_text,
                "score": dup["score"] * 0.5,
                "duplicate_of": dup["duplicate_of"],
                "metadata": {**dup["metadata"], "duplicate_note": True},
            })
            used_bytes += note_size
            used_files += 1

    selected.extend(duplicate_notes)
    selected.sort(key=lambda c: c["score"], reverse=True)

    selected_paths = {c["path"] for c in selected}

    overflow_notes = []
    for candidate in unique_candidates:
        if candidate["path"] in selected_paths:
            continue
        if len(overflow_notes) >= OVERFLOW_SUMMARY_LIMIT:
            break
        highlights = summarize_structure(candidate["text"], OVERFLOW_SUMMARY_LINES)
        summary_lines = ["[summary only: file summarized to conserve tokens]"]
        if highlights:
            summary_lines.extend(f"- {h}" for h in highlights)
        else:
            summary_lines.append("- Structure summary unavailable (no salient lines detected).")
        summary_text = "\n".join(summary_lines)
        summary_size = len(summary_text.encode("utf-8"))
        if used_files >= max_files or used_bytes + summary_size > max_total_bytes:
            break
        overflow_notes.append({
            "path": candidate["path"],
            "size": summary_size,
            "truncated": False,
            "text": summary_text,
            "score": candidate["score"] * 0.4,
            "duplicate_of": None,
            "metadata": {**candidate["metadata"], "summary_only": True},
        })
        used_bytes += summary_size
        used_files += 1

    selected.extend(overflow_notes)
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
        ""
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


def build_final_system_prompt() -> str:
    return (
        "You are VulnSherif, an expert application security auditor. "
        "Analyze the provided website/application source code for security vulnerabilities, "
        "misconfigurations, insecure defaults, and risky patterns. Prioritize actionable, accurate findings.\n\n"
        "Guidelines:\n"
        "- Assume modern best practices (OWASP ASVS, Top 10, CWE).\n"
        "- Identify: severity (Critical/High/Medium/Low), impact, likelihood, affected files, and code snippets.\n"
        "- Provide concrete remediation guidance (no code patches required).\n"
        "- Prefer minimal, targeted fixes.\n"
        "- If context is insufficient, note assumptions explicitly.\n\n"
        "Output Formatting:\n"
        "1) A detailed executive summary (2-3 sentences) that references key modules or workflows and explains overall risk.\n"
        "2) A JSON block with the following shape (include all material findings, sorted by severity descending; no limit on count):\n"
        "{\n"
        "\"summary\": \"...\",\n"
        "\"findings\": [\n"
        "  {\n"
        "    \"title\": \"...\",\n"
        "    \"severity\": \"Critical|High|Medium|Low\",\n"
        "    \"category\": \"Short vulnerability category (e.g., SQL Injection)\",\n"
        "    \"files\": [\"path1\", \"path2\"],\n"
        "    \"cve_id\": \"CVE-YYYY-NNNN if confidently mapped, otherwise 'N/A'\",\n"
        "    \"cvss_score\": \"Base score with vector if available (e.g., 9.8 CRITICAL (AV:N/AC:L/...))\",\n"
        "    \"description\": \"Why this matters (impact + likelihood). Reference specific code lines.\",\n"
        "    \"evidence\": \"Concise code snippet or reference path:line\",\n"
        "    \"remediation\": \"Specific actions to fix (bulleted sentences)\"\n"
        "  }\n"
        "]\n"
        "}\n"
        "Only include CVE IDs that confidently map to the described vulnerability after double-checking the code context; otherwise set cve_id to 'N/A'. "
        "Ensure CVSS scores, if provided, correspond to the referenced CVE.\n"
        "3) Then a human-readable detailed report."
    )


def build_per_file_system_prompt() -> str:
    return (
        "You are VulnSherif, reviewing a single source file for security issues. "
        "Focus strictly on the provided file content. Identify concrete vulnerabilities, "
        "misconfigurations, or risky patterns present in this file. "
        "Avoid speculation beyond the code shown.\n\n"
        "Respond with a JSON object:\n"
        "{\n"
        "  \"file_path\": \"...\",\n"
        "  \"summary\": \"Short summary for this file\",\n"
        "  \"findings\": [\n"
        "    {\n"
        "      \"title\": \"...\",\n"
        "      \"severity\": \"Critical|High|Medium|Low\",\n"
        "      \"category\": \"Short category (e.g., SQL Injection)\",\n"
        "      \"cve_id\": \"CVE-YYYY-NNNN if confidently mapped, otherwise 'N/A'\",\n"
        "      \"cvss_score\": \"Score and vector if known\",\n"
        "      \"description\": \"Impact and likelihood grounded in this file\",\n"
        "      \"evidence\": \"Code snippet or line reference\",\n"
        "      \"remediation\": \"Targeted fix guidance\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "Return an empty findings array if no issues are present. "
        "Only cite CVEs that accurately match the vulnerability evidenced in this file.\n"
    )


def build_final_user_payload(per_file_results: List[Dict[str, Any]], notes: str) -> str:
    payload = {
        "notes": notes.strip(),
        "files": per_file_results,
    }
    return json.dumps(payload, indent=2)


def _response_text_from_gemini(response: Any) -> str:
    if response is None:
        return ""
    text = getattr(response, "text", None)
    if text:
        return text
    parts: List[str] = []
    for candidate in getattr(response, "candidates", []) or []:
        content = getattr(candidate, "content", None)
        if not content:
            continue
        candidate_parts = getattr(content, "parts", None)
        if candidate_parts is None:
            # to_dict fallback
            try:
                candidate_dict = candidate.to_dict()  # type: ignore[attr-defined]
                for part in candidate_dict.get("content", {}).get("parts", []):
                    value = part.get("text") or part.get("stringValue")
                    if value:
                        parts.append(value)
                continue
            except Exception:
                continue
        for part in candidate_parts:
            value = getattr(part, "text", None) or getattr(part, "string_value", None)
            if value:
                parts.append(value)
    return "\n".join(parts).strip()


def call_gemini_generate(api_key: str,
                         model: str,
                         system_prompt: str,
                         user_content: str,
                         temperature: float = 0.2,
                         timeout: int = 120,
                         max_output_tokens: int = 4096) -> str:
    ensure_gemini_client(api_key)
    generation_config = {
        "temperature": temperature,
        "max_output_tokens": max_output_tokens,
    }
    model_instance = genai.GenerativeModel(
        model_name=model,
        system_instruction=system_prompt,
    )
    request_options = {"timeout": timeout}
    try:
        response = model_instance.generate_content(
            [{"role": "user", "parts": [user_content]}],
            generation_config=generation_config,
            request_options=request_options,
        )
    except TypeError:
        # Older SDK versions may not support request_options
        response = model_instance.generate_content(
            [{"role": "user", "parts": [user_content]}],
            generation_config=generation_config,
        )
    feedback = getattr(response, "prompt_feedback", None)
    if feedback and getattr(feedback, "block_reason", None):
        raise RuntimeError(f"Gemini blocked the request: {feedback.block_reason}")
    text = _response_text_from_gemini(response)
    if not text:
        raise RuntimeError("Gemini returned an empty response.")
    return text


def _extract_first_json_object(text: str) -> Optional[str]:
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1]
    return None


def _escape_control_chars_in_strings(text: str) -> str:
    if not text:
        return text
    result: List[str] = []
    in_string = False
    escape = False
    i = 0
    length = len(text)
    whitespace = {" ", "\t", "\n", "\r"}
    while i < length:
        ch = text[i]
        if escape:
            result.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\":
            result.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"':
            if in_string:
                j = i + 1
                while j < length and text[j] in whitespace:
                    j += 1
                if j < length and text[j] not in {",", "}", "]", ":"}:
                    result.append("\\\"")
                    i += 1
                    continue
                in_string = False
                result.append(ch)
                i += 1
                continue
            else:
                in_string = True
                result.append(ch)
                i += 1
                continue
        if in_string and ch in {"\n", "\r", "\t"}:
            if ch == "\n":
                result.append("\\n")
            elif ch == "\r":
                result.append("\\r")
            else:
                result.append("\\t")
            i += 1
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def try_extract_json_block(text: str):
    if not text:
        return None
    fences = [("```json", "```"), ("```", "```")]
    for start, end in fences:
        s = text.find(start)
        if s != -1:
            e = text.find(end, s + len(start))
            if e != -1:
                candidate = text[s + len(start):e].strip()
                try:
                    return json.loads(candidate)
                except Exception:
                    pass
    try:
        return json.loads(text)
    except Exception:
        pass
    candidate = _extract_first_json_object(text)
    if candidate:
        sanitized = _escape_control_chars_in_strings(candidate)
        try:
            return json.loads(sanitized)
        except Exception:
            return None
    return None


# ----------------------------
# ROUTES
# ----------------------------
@app.get("/")
def index():
    return render_template(
        "desired-web.html",
        max_files=MAX_FILES,
        max_total=format_bytes(MAX_TOTAL_BYTES),
        max_file=format_bytes(MAX_FILE_BYTES),
    )


@app.post("/analyze")
def analyze():
    api_key = app.config.get(API_KEY_ENV_VAR) or os.getenv(API_KEY_ENV_VAR, "")
    model = FORCED_MODEL
    notes = request.form.get("notes") or ""
    temperature = DEFAULT_TEMPERATURE

    prompt_only = bool(request.form.get("prompt_only"))
    debug_mode = bool(request.form.get("debug")) or bool(os.getenv("VULNSHERIF_DEBUG"))
    dry_run = bool(request.form.get("dry_run"))
    file = request.files.get("zip_file")
    if not api_key:
        flash("Missing Gemini API key.", "error")
        return redirect(url_for("index"))
    try:
        ensure_gemini_client(api_key)
        app.config[API_KEY_ENV_VAR] = api_key
        os.environ[API_KEY_ENV_VAR] = api_key
    except Exception as exc:
        flash(f"Gemini client initialization failed: {exc}", "error")
        logger.error(f"Gemini client initialization failed: {exc}")
        return redirect(url_for("index"))
    if (not file or file.filename == "") and not prompt_only and not notes.strip():
        flash("Upload a ZIP or enter notes (prompt-only).", "error")
        return redirect(url_for("index"))
    if file and file.filename != "" and not file.filename.lower().endswith(".zip"):
        flash("Only .zip files are supported.", "error")
        return redirect(url_for("index"))

    req_id = str(uuid.uuid4())
    logger.info(f"[{req_id}] queued analysis model={model} prompt_only={prompt_only} dry_run={dry_run}")

    zip_temp_path = None
    file = request.files.get("zip_file")
    try:
        if file and file.filename != "":
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            file.stream.seek(0)
            tmp_file.write(file.read())
            tmp_file.close()
            zip_temp_path = tmp_file.name
    except Exception as exc:
        if zip_temp_path:
            try:
                os.unlink(zip_temp_path)
            except Exception:
                pass
        logger.exception(f"Failed to persist uploaded ZIP: {exc}")
        flash("Failed to read uploaded ZIP.", "error")
        return redirect(url_for("index"))

    init_job(req_id)
    update_job_progress(req_id, "queued", "Job queued")
    perform_analysis_job(
        req_id=req_id,
        api_key=api_key,
        zip_path=zip_temp_path,
        notes=notes,
        prompt_only=prompt_only,
        dry_run=dry_run,
        debug_mode=debug_mode,
        temperature=temperature,
    )
    data = get_job(req_id)
    if not data:
        context = build_frontend_error_payload("Analysis completed, but the result could not be retrieved.")
        with progress_lock:
            job_store.pop(req_id, None)
        return render_template("desired-result.html", **context), 500
    return redirect(url_for("job_result", req_id=req_id), code=303)


@app.get("/progress/<req_id>")
def progress(req_id: str):
    data = get_job(req_id)
    if not data:
        abort(404)
    return jsonify({k: v for k, v in data.items() if k != "result"})


@app.get("/status/<req_id>")
def job_status(req_id: str):
    data = get_job(req_id)
    if not data:
        return jsonify({"status": "unknown", "error": "Job not found"}), 404
    return jsonify(data)


@app.get("/result/<req_id>")
def job_result(req_id: str):
    data = get_job(req_id)
    if not data:
        abort(404)
    status = data.get("status")
    if status == "completed":
        result_context = data.get("result") or {}
        with progress_lock:
            job_store.pop(req_id, None)
        payload = build_frontend_payload(result_context)
        payload["req_id"] = req_id
        return render_template("desired-result.html", **payload)
    if status == "failed":
        error_message = data.get("error", "Job failed.")
        with progress_lock:
            job_store.pop(req_id, None)
        payload = build_frontend_error_payload(error_message)
        payload["req_id"] = req_id
        return render_template("desired-result.html", **payload), 500
    return redirect(url_for("progress", req_id=req_id))

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Prompt on first run to capture and save API key (avoid double prompt on reloader)
    if not os.getenv("WERKZEUG_RUN_MAIN"):
        try:
            ensure_api_key_interactive()
        except Exception as e:
            print(f"Failed to initialize API key: {e}")
            sys.exit(1)
    port = int(os.getenv("PORT", "5000"))
    debug_flag = bool(os.getenv("FLASK_DEBUG")) or bool(os.getenv("VULNSHERIF_DEBUG"))
    app.run(host="127.0.0.1", port=port, debug=debug_flag)
