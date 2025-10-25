import os
import io
import json
import time
import uuid
import zipfile
import shutil
import tempfile
import logging
from typing import List, Tuple, Dict

import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify


# ----------------------------
# FLASK APP CONFIG
# ----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB upload cap


# ----------------------------
# CONSTANTS
# ----------------------------
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openrouter/auto"
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


# ----------------------------
# HELPERS
# ----------------------------
def setup_logger():
    level_name = os.getenv("VULNSHERIF_LOG_LEVEL") or ("DEBUG" if os.getenv("VULNSHERIF_DEBUG") else "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    return logging.getLogger("vulnsherif")


logger = setup_logger()
def format_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


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
    selected = []
    total_bytes = 0
    file_count = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in ignore_dirs and not d.startswith('.')]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root_dir).replace("\\", "/")
            if not is_text_file(fpath):
                continue
            if file_count >= max_files or total_bytes >= max_total_bytes:
                break

            try:
                with open(fpath, "rb") as f:
                    raw = f.read(max_file_bytes + 1)
            except Exception:
                continue

            truncated = len(raw) > max_file_bytes
            content = raw[:max_file_bytes]

            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    text = content.decode("latin-1")
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

        if file_count >= max_files or total_bytes >= max_total_bytes:
            break

    return selected, file_count, total_bytes


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
    for f in files:
        header = f"--- file: {f['path']} ({format_bytes(f['size'])})"
        body = f["text"]
        if f["truncated"]:
            body = body.rstrip() + "\n...TRUNCATED"
        parts.append(header)
        parts.append("```")
        parts.append(body)
        parts.append("```")
        parts.append("")
    return "\n".join(parts)


def build_system_prompt() -> str:
    return (
        "You are VulnSherif, an expert application security auditor. "
        "Analyze the provided website/application source code for security vulnerabilities, "
        "misconfigurations, insecure defaults, and risky patterns. Prioritize actionable, accurate findings.\n\n"
        "Guidelines:\n"
        "- Assume modern best practices (OWASP ASVS, Top 10, CWE).\n"
        "- Identify: severity (Critical/High/Medium/Low), impact, likelihood, affected files, and code snippets.\n"
        "- Provide concrete remediation with code patches or configuration changes.\n"
        "- Prefer minimal, targeted fixes.\n"
        "- If context is insufficient, state assumptions and offer validation steps.\n\n"
        "Output Formatting:\n"
        "1) A concise executive summary.\n"
        "2) A JSON block with the following shape (keep it compact):\n"
        "{\n"
        "\"summary\": \"...\",\n"
        "\"findings\": [\n"
        "  {\n"
        "    \"title\": \"...\",\n"
        "    \"severity\": \"Critical|High|Medium|Low\",\n"
        "    \"cwe\": \"CWE-XXX (name)\",\n"
        "    \"owasp\": \"AXX (name)\",\n"
        "    \"files\": [\"path1\", \"path2\"],\n"
        "    \"description\": \"...\",\n"
        "    \"evidence\": \"short snippet or reference\",\n"
        "    \"remediation\": \"specific steps\",\n"
        "    \"patch\": \"unified diff or code block if feasible\"\n"
        "  }\n"
        "]\n"
        "}\n"
        "3) Then a human-readable detailed report."
    )


def call_openrouter(api_key: str, model: str, messages: List[Dict], temperature: float = 0.2, timeout: int = 120) -> Dict:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "X-Title": "VulnSherif",
        "HTTP-Referer": "http://localhost"
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    redacted_headers = {k: ("Bearer ****" if k.lower() == "authorization" else v) for k, v in headers.items()}
    logger.debug(f"Calling OpenRouter url={OPENROUTER_API_URL} model={model} temp={temperature} headers={redacted_headers}")
    resp = requests.post(OPENROUTER_API_URL, headers=headers, json=payload, timeout=timeout)
    logger.debug(f"OpenRouter status={resp.status_code} bytes={len(resp.content)}")
    if resp.status_code != 200:
        raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text}")
    return resp.json()


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
        return None


# ----------------------------
# ROUTES
# ----------------------------
@app.get("/")
def index():
    return render_template(
        "index.html",
        default_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        default_model=DEFAULT_MODEL,
        max_files=MAX_FILES,
        max_total=format_bytes(MAX_TOTAL_BYTES),
        max_file=format_bytes(MAX_FILE_BYTES),
    )


@app.post("/analyze")
def analyze():
    api_key = request.form.get("api_key") or os.getenv("OPENROUTER_API_KEY", "")
    model = request.form.get("model") or DEFAULT_MODEL
    notes = request.form.get("notes") or ""
    try:
        temperature = float(request.form.get("temperature", 0.2))
    except ValueError:
        temperature = 0.2

    prompt_only = bool(request.form.get("prompt_only"))
    debug_mode = bool(request.form.get("debug")) or bool(os.getenv("VULNSHERIF_DEBUG"))
    dry_run = bool(request.form.get("dry_run"))
    req_id = str(uuid.uuid4())
    logger.info(f"[{req_id}] analyze start model={model} temp={temperature} prompt_only={prompt_only} dry_run={dry_run}")
    file = request.files.get("zip_file")
    if not api_key:
        flash("Missing OpenRouter API key.", "error")
        return redirect(url_for("index"))
    # Validate inputs: allow prompt-only mode without ZIP, but require at least some notes
    if (not file or file.filename == "") and not prompt_only and not notes.strip():
        flash("Upload a ZIP or enter notes (prompt-only).", "error")
        return redirect(url_for("index"))
    if file and file.filename != "" and not file.filename.lower().endswith(".zip"):
        flash("Only .zip files are supported.", "error")
        return redirect(url_for("index"))

    start = time.time()
    tmp_root = tempfile.mkdtemp(prefix="vulnsherif_")
    try:
        files = []
        if file and file.filename != "":
            try:
                with zipfile.ZipFile(io.BytesIO(file.read())) as zf:
                    logger.debug(f"[{req_id}] extracting ZIP to {tmp_root}")
                    safe_extract_zip(zf, tmp_root)
            except zipfile.BadZipFile:
                flash("Invalid ZIP archive.", "error")
                return redirect(url_for("index"))

            files, count, total = collect_files(tmp_root)
            logger.debug(f"[{req_id}] collected files count={len(files)} total_bytes={sum(f['size'] for f in files)}")
        packaged = format_files_for_prompt(files)
        packaged_preview = packaged[:20000] + ("\n... [truncated view]" if len(packaged) > 20000 else "")
        packaged_len = len(packaged.encode("utf-8", errors="ignore"))
        logger.debug(f"[{req_id}] packaged context bytes={packaged_len}")

        system_prompt = build_system_prompt()
        user_content = (f"User Context:\n{notes.strip()}\n\n" if notes.strip() else "") + packaged
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        debug_details = {
            "request_id": req_id,
            "model": model,
            "temperature": temperature,
            "files_included": len(files),
            "packaged_bytes": packaged_len,
            "notes_len": len(notes),
            "prompt_only": prompt_only,
            "dry_run": dry_run,
            "system_prompt_len": len(system_prompt),
            "user_content_len": len(user_content),
        }

        if dry_run:
            logger.info(f"[{req_id}] dry-run: skipping OpenRouter call")
            elapsed = time.time() - start
            return render_template(
                "result.html",
                content="[Dry Run] Skipped OpenRouter call.",
                response_json={
                    "endpoint": OPENROUTER_API_URL,
                    "headers": {"Authorization": "Bearer ****", "X-Title": "VulnSherif", "HTTP-Referer": "http://localhost"},
                    "payload": {"model": model, "messages": "omitted", "temperature": temperature},
                },
                parsed_json=None,
                files_included=len(files),
                max_files=MAX_FILES,
                text_size=format_bytes(sum(f["size"] for f in files)),
                model=model,
                temperature=temperature,
                elapsed=f"{elapsed:.1f}s",
                packaged_preview=packaged_preview,
                debug_details=debug_details,
                debug_mode=debug_mode,
            )

        logger.info(f"[{req_id}] calling OpenRouter")
        resp = call_openrouter(api_key, model, messages, temperature=temperature)
        elapsed = time.time() - start
        logger.info(f"[{req_id}] OpenRouter ok in {elapsed:.2f}s")

        content = None
        try:
            content = resp.get("choices", [{}])[0].get("message", {}).get("content")
        except Exception:
            pass

        parsed = try_extract_json_block(content or "")

        return render_template(
            "result.html",
            content=content,
            response_json=resp if not content else None,
            parsed_json=parsed,
            files_included=len(files),
            max_files=MAX_FILES,
            text_size=format_bytes(sum(f["size"] for f in files)),
            model=model,
            temperature=temperature,
            elapsed=f"{elapsed:.1f}s",
            packaged_preview=packaged_preview,
            debug_details=debug_details,
            debug_mode=debug_mode,
        )
    except requests.exceptions.Timeout:
        logger.exception(f"[{req_id}] OpenRouter timeout")
        flash("OpenRouter request timed out. Try lower payload or a different model.", "error")
        return redirect(url_for("index"))
    except requests.exceptions.ConnectionError as e:
        logger.exception(f"[{req_id}] connection error: {e}")
        flash("Network error connecting to OpenRouter. Check internet/firewall.", "error")
        return redirect(url_for("index"))
    except Exception as e:
        logger.exception(f"[{req_id}] Processing failed: {e}")
        flash(f"Processing failed: {e}", "error")
        return redirect(url_for("index"))
    finally:
        try:
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug_flag = bool(os.getenv("FLASK_DEBUG")) or bool(os.getenv("VULNSHERIF_DEBUG"))
    app.run(host="127.0.0.1", port=port, debug=debug_flag)
