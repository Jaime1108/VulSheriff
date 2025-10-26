"""Core analysis workflow orchestration."""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import zipfile
from typing import Dict, List, Optional

from .config import (
    AGGREGATE_CONTENT_PREVIEW_CHARS,
    FORCED_MODEL,
    MAX_PER_FILE_ANALYSES,
    MAX_FILES,
)
from .file_utils import collect_files, format_files_for_prompt, safe_extract_zip
from .gemini_service import (
    call_model_for_aggregate,
    call_model_for_file,
    ensure_gemini_client,
)
from .job_store import (
    complete_job,
    fail_job,
    job_store,
    progress_lock,
    update_job_progress,
)
from .reporting import SEVERITY_LABELS, build_report, normalize_severity
from .text_utils import format_bytes

import logging

logger = logging.getLogger("vulnsherif")


def build_scan_meta(
    req_id: str,
    files: List[Dict[str, Any]],
    elapsed_seconds: float,
    model: str,
    temperature: float,
    packaged_bytes: int,
    notes: str,
    prompt_only: bool,
) -> Dict[str, Any]:
    total_bytes = sum(f.get("size", 0) for f in files)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
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


def perform_analysis_job(
    req_id: str,
    api_key: str,
    zip_path: Optional[str],
    single_file: Optional[Dict[str, Any]],
    notes: str,
    prompt_only: bool,
    dry_run: bool,
    debug_mode: bool,
    temperature: float,
) -> None:
    start = time.time()
    update_job_progress(req_id, "init", "Preparing analysis inputs")
    tmp_root = tempfile.mkdtemp(prefix="vulnsherif_job_")
    files: List[Dict[str, Any]] = []
    packaged_len = 0
    analyzable_files: List[Dict[str, Any]] = []
    per_file_results: List[Dict[str, Any]] = []
    notes_only_mode = bool(notes.strip() and not zip_path and not single_file)
    try:
        if not api_key:
            raise RuntimeError("Missing Gemini API key.")
        ensure_gemini_client(api_key)
        upload_available = False
        if zip_path:
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    update_job_progress(req_id, "files", "Extracting ZIP archive")
                    safe_extract_zip(zf, tmp_root)
            except zipfile.BadZipFile as exc:
                raise RuntimeError("Invalid ZIP archive.") from exc
            upload_available = True
        elif single_file:
            filename = (single_file.get("filename") or "").strip()
            filename = os.path.basename(filename)
            if not filename:
                filename = "uploaded_file"
            if not os.path.splitext(filename)[1]:
                filename = f"{filename}.txt"
            data = single_file.get("data")
            if data is None:
                raise RuntimeError("Uploaded file is empty.")
            if isinstance(data, str):
                data = data.encode("utf-8", errors="ignore")
            if not data:
                raise RuntimeError("Uploaded file is empty.")
            dest_path = os.path.join(tmp_root, filename)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as dest:
                dest.write(data)
            upload_available = True
        effective_prompt_only = prompt_only
        if notes_only_mode:
            effective_prompt_only = False
        allow_analysis_without_files = notes_only_mode or prompt_only

        if upload_available or allow_analysis_without_files:
            files, _, total = collect_files(tmp_root)
            if upload_available:
                update_job_progress(
                    req_id, "files", f"Collected {len(files)} files ({format_bytes(total)})"
                )
        else:
            raise RuntimeError(
                "Upload a ZIP, a supported text file, or provide notes for context."
            )

        packaged = format_files_for_prompt(files)
        packaged_len = len(packaged.encode("utf-8", errors="ignore"))
        analyzable_files = [
            f
            for f in files
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
                prompt_only=effective_prompt_only or notes_only_mode,
            )
            scan_meta["notes_only"] = notes_only_mode
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
        for file_item in analyzable_files:
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
            per_file_results.append(
                {
                    "file_path": path,
                    "summary": "Not analyzed directly (token budget); covered via aggregated context.",
                    "findings": [],
                    "content_preview": (file_item.get("text") or "")[
                        :AGGREGATE_CONTENT_PREVIEW_CHARS
                    ],
                }
            )
        if not per_file_results and allow_analysis_without_files:
            per_file_results.append(
                {
                    "file_path": "prompt_only",
                    "summary": "No files analyzed; report based on user context.",
                    "findings": [],
                    "content_preview": notes[:AGGREGATE_CONTENT_PREVIEW_CHARS],
                }
            )

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
            prompt_only=effective_prompt_only,
        )
        scan_meta["notes_only"] = notes_only_mode

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
        logger.exception("[%s] analysis job failed: %s", req_id, exc)
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


__all__ = ["perform_analysis_job", "build_scan_meta"]
