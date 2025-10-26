"""In-memory job tracking utilities."""

from __future__ import annotations

import json
import time
from threading import Lock
from typing import Any, Dict, Optional

job_store: Dict[str, Dict[str, Any]] = {}
progress_lock = Lock()


def init_job(req_id: str) -> None:
    with progress_lock:
        job_store[req_id] = {
            "status": "running",
            "progress": [],
            "result": None,
            "error": None,
            "started_at": time.time(),
        }


def update_job_progress(
    req_id: str, stage: str, detail: Optional[str] = None, state: str = "running"
) -> None:
    with progress_lock:
        entry = job_store.get(req_id)
        if not entry:
            return
        if state in {"running", "queued", "waiting", "completed", "failed"}:
            entry["status"] = state
        entry["progress"].append(
            {
                "timestamp": time.time(),
                "stage": stage,
                "detail": detail or "",
                "state": state,
            }
        )


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


__all__ = [
    "job_store",
    "progress_lock",
    "init_job",
    "update_job_progress",
    "complete_job",
    "fail_job",
    "get_job",
]
