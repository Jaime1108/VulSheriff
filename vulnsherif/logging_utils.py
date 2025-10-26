"""Logging helpers and graceful shutdown support."""

from __future__ import annotations

import logging
import os
import signal
from concurrent.futures import ThreadPoolExecutor


def setup_logger(name: str = "vulnsherif") -> logging.Logger:
    level_name = os.getenv("VULNSHERIF_LOG_LEVEL") or (
        "DEBUG" if os.getenv("VULNSHERIF_DEBUG") else "INFO"
    )
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def register_shutdown_signals(logger: logging.Logger, executor: ThreadPoolExecutor) -> None:
    def _shutdown_handler(signum, _frame):
        logger.warning(
            "Received shutdown signal (%s); cancelling pending work and exiting.", signum
        )
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

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _shutdown_handler)
        except (AttributeError, ValueError):
            continue
