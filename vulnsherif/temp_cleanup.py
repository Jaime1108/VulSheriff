"""Helpers to remove stale temp directories before new sessions."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Optional


JOB_DIR_PREFIX = "vulnsherif_job_"


def cleanup_job_temp_dirs(logger: Optional[object] = None) -> None:
    """Remove temporary job directories created by previous runs."""
    base = Path(tempfile.gettempdir())
    if not base.exists():
        return
    for path in base.glob(f"{JOB_DIR_PREFIX}*"):
        if not path.is_dir():
            continue
        try:
            shutil.rmtree(path, ignore_errors=True)
            if logger:
                getattr(logger, "debug", lambda *_: None)(
                    "Removed stale temp directory %s", path
                )
        except Exception as exc:  # pragma: no cover - best effort cleanup
            if logger:
                getattr(logger, "warning", lambda *_: None)(
                    "Failed to remove temp directory %s: %s", path, exc
                )
