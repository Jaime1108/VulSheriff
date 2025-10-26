"""Flask application setup and route definitions."""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from typing import Dict, Optional

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from .analysis_runner import perform_analysis_job
from .api_keys import ensure_api_key_interactive
from .config import (
    API_KEY_ENV_VAR,
    DEFAULT_TEMPERATURE,
    EXECUTOR_MAX_WORKERS,
    FORCED_MODEL,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
)
from .gemini_service import ensure_gemini_client
from .job_store import get_job, init_job, job_store, progress_lock, update_job_progress
from .logging_utils import register_shutdown_signals, setup_logger
from .reporting import build_frontend_error_payload, build_frontend_payload
from .text_utils import format_bytes
from .temp_cleanup import cleanup_job_temp_dirs

import logging
from concurrent.futures import ThreadPoolExecutor

logger = setup_logger()


def create_app() -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    template_dir = project_root / "templates"
    static_dir = project_root / "static"
    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64MB upload limit
    app.config[API_KEY_ENV_VAR] = os.environ.get(API_KEY_ENV_VAR, "")

    if app.config.get(API_KEY_ENV_VAR):
        logger.info("Detected GEMINI_API_KEY from environment/.env")
    else:
        logger.warning(
            "GEMINI_API_KEY not set; will prompt on first run and store securely in user config."
        )

    executor = ThreadPoolExecutor(max_workers=max(1, EXECUTOR_MAX_WORKERS))
    register_shutdown_signals(logger, executor)
    app.extensions["vulnsherif_executor"] = executor

    register_routes(app)
    return app


def register_routes(app: Flask) -> None:
    @app.get("/")
    def index():
        cleanup_job_temp_dirs(logger)
        return render_template(
            "desired-web.html",
            max_files=MAX_FILES,
            max_total=format_bytes(MAX_TOTAL_BYTES),
            max_file=format_bytes(MAX_FILE_BYTES),
        )

    @app.post("/analyze")
    def analyze():
        api_key = app.config.get(API_KEY_ENV_VAR) or os.getenv(API_KEY_ENV_VAR, "")
        notes = request.form.get("notes") or ""
        temperature = DEFAULT_TEMPERATURE

        prompt_only = bool(request.form.get("prompt_only"))
        debug_mode = bool(request.form.get("debug")) or bool(
            os.getenv("VULNSHERIF_DEBUG")
        )
        dry_run = bool(request.form.get("dry_run"))
        file = request.files.get("zip_file")
        has_upload = bool(file and file.filename)
        if has_upload:
            prompt_only = False

        if not api_key:
            flash("Missing Gemini API key.", "error")
            return redirect(url_for("index"))
        try:
            ensure_gemini_client(api_key)
            app.config[API_KEY_ENV_VAR] = api_key
            os.environ[API_KEY_ENV_VAR] = api_key
        except Exception as exc:
            flash(f"Gemini client initialization failed: {exc}", "error")
            logger.error("Gemini client initialization failed: %s", exc)
            return redirect(url_for("index"))
        if (not file or file.filename == "") and not prompt_only and not notes.strip():
            flash("Upload a file or enter notes (prompt-only).", "error")
            return redirect(url_for("index"))

        req_id = str(uuid.uuid4())
        logger.info(
            "[%s] queued analysis model=%s prompt_only=%s dry_run=%s",
            req_id,
            FORCED_MODEL,
            prompt_only,
            dry_run,
        )

        zip_temp_path = None
        single_file_payload: Optional[Dict[str, bytes]] = None
        file = request.files.get("zip_file")
        try:
            if file and file.filename != "":
                file.stream.seek(0)
                filename = file.filename
                if filename.lower().endswith(".zip"):
                    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
                    tmp_file.write(file.read())
                    tmp_file.close()
                    zip_temp_path = tmp_file.name
                else:
                    data = file.read()
                    if not data:
                        raise ValueError("Uploaded file is empty.")
                    single_file_payload = {"filename": filename, "data": data}
        except Exception as exc:
            if zip_temp_path:
                try:
                    os.unlink(zip_temp_path)
                except Exception:
                    pass
            logger.exception("Failed to persist uploaded file: %s", exc)
            flash("Failed to read uploaded file.", "error")
            return redirect(url_for("index"))

        init_job(req_id)
        update_job_progress(req_id, "queued", "Job queued")
        perform_analysis_job(
            req_id=req_id,
            api_key=api_key,
            zip_path=zip_temp_path,
            single_file=single_file_payload,
            notes=notes,
            prompt_only=prompt_only,
            dry_run=dry_run,
            debug_mode=debug_mode,
            temperature=temperature,
        )
        data = get_job(req_id)
        if not data:
            context = build_frontend_error_payload(
                "Analysis completed, but the result could not be retrieved."
            )
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


__all__ = ["create_app"]
