"""Gemini client helpers and model invocation utilities."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
except ImportError:  # pragma: no cover - handled at runtime
    genai = None  # type: ignore[assignment]
    google_exceptions = None  # type: ignore[assignment]

from .config import (
    AGGREGATE_CONTENT_PREVIEW_CHARS,
    PER_FILE_MAX_RETRIES,
    RATE_LIMIT_MIN_DELAY,
)

logger = logging.getLogger("vulnsherif")
rate_limit_lock = threading.Lock()
last_model_call = {"timestamp": 0.0}
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


def wait_for_rate_limit(min_delay: float = RATE_LIMIT_MIN_DELAY) -> None:
    if min_delay <= 0:
        return
    with rate_limit_lock:
        now = time.time()
        elapsed = now - last_model_call["timestamp"]
        if elapsed < min_delay:
            time.sleep(min_delay - elapsed)
        last_model_call["timestamp"] = time.time()


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


def call_gemini_generate(
    api_key: str,
    model: str,
    system_prompt: str,
    user_content: str,
    *,
    temperature: float = 0.2,
    timeout: int = 120,
    max_output_tokens: int = 4096,
) -> str:
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
                return text[start : idx + 1]
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
                    result.append('\\"')
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
                candidate = text[s + len(start) : e].strip()
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


def call_model_for_file(
    api_key: str,
    model: str,
    file_item: Dict[str, Any],
    temperature: float,
    req_id: str,
    *,
    timeout: int = 120,
    progress_cb=None,
) -> Optional[Dict[str, Any]]:
    from .prompts import build_per_file_system_prompt

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
                    "[%s] per-file JSON missing for %s. excerpt=%r",
                    req_id,
                    file_item.get("path"),
                    snippet[:200],
                )
                if progress_cb:
                    progress_cb(
                        f"file:{file_item.get('path')}",
                        "No structured JSON",
                        state="warning",
                    )
                return None
            parsed.setdefault("file_path", file_item.get("path"))
            preview = file_text[:AGGREGATE_CONTENT_PREVIEW_CHARS]
            if preview:
                parsed.setdefault("content_preview", preview)
            if progress_cb:
                progress_cb(f"file:{file_item.get('path')}", "Completed", state="success")
            return parsed
        except Exception as exc:
            if google_exceptions and isinstance(exc, google_exceptions.ResourceExhausted):
                wait_seconds = 8.0
                retry_delay = getattr(exc, "retry_delay", None)
                if retry_delay:
                    try:
                        wait_seconds = max(
                            wait_seconds, float(retry_delay.total_seconds())
                        )
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
                logger.warning(
                    "[%s] rate limit on %s attempt %s: %s",
                    req_id,
                    file_item.get("path"),
                    attempt,
                    exc,
                )
                time.sleep(wait_seconds)
                continue
            if isinstance(exc, RuntimeError):
                logger.warning(
                    "[%s] per-file analysis failed for %s: %s",
                    req_id,
                    file_item.get("path"),
                    exc,
                )
                if progress_cb:
                    progress_cb(f"file:{file_item.get('path')}", "Failed", state="error")
                return None
            if google_exceptions and isinstance(exc, google_exceptions.GoogleAPIError):
                logger.warning(
                    "[%s] Gemini API error for %s: %s",
                    req_id,
                    file_item.get("path"),
                    exc,
                )
                if progress_cb:
                    progress_cb(f"file:{file_item.get('path')}", "API error", state="error")
                return None
            logger.warning(
                "[%s] per-file analysis failed for %s: %s",
                req_id,
                file_item.get("path"),
                exc,
            )
            if progress_cb:
                progress_cb(f"file:{file_item.get('path')}", "Failed", state="error")
            return None
    logger.warning(
        "[%s] per-file retries exhausted for %s",
        req_id,
        file_item.get("path"),
    )
    if progress_cb:
        progress_cb(f"file:{file_item.get('path')}", "Failed after retries", state="error")
    return None


def call_model_for_aggregate(
    api_key: str,
    model: str,
    per_file_results: List[Dict[str, Any]],
    notes: str,
    temperature: float,
    req_id: str,
    *,
    timeout: int = 180,
    progress_cb=None,
) -> Optional[Dict[str, Any]]:
    from .prompts import build_final_system_prompt, build_final_user_payload

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
                logger.error(
                    "[%s] aggregate JSON missing. excerpt=%r", req_id, snippet[:400]
                )
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
                        wait_seconds = max(
                            wait_seconds, float(retry_delay.total_seconds())
                        )
                    except Exception:
                        try:
                            wait_seconds = max(wait_seconds, float(retry_delay))
                        except Exception:
                            pass
                if attempt < PER_FILE_MAX_RETRIES:
                    if progress_cb:
                        progress_cb(
                            "aggregate",
                            f"Rate limited; retrying in {wait_seconds:.0f}s",
                            state="waiting",
                        )
                    logger.warning(
                        "[%s] aggregate rate limit attempt %s: %s",
                        req_id,
                        attempt,
                        exc,
                    )
                    time.sleep(wait_seconds)
                    continue
            if isinstance(exc, RuntimeError):
                logger.error("[%s] aggregate analysis failed: %s", req_id, exc)
                if progress_cb:
                    progress_cb("aggregate", f"Failed: {exc}", state="error")
                return None
            if google_exceptions and isinstance(exc, google_exceptions.GoogleAPIError):
                logger.error("[%s] aggregate Gemini API error: %s", req_id, exc)
                if progress_cb:
                    progress_cb("aggregate", f"API error: {exc}", state="error")
                return None
            logger.error("[%s] aggregate analysis failed: %s", req_id, exc)
            if progress_cb:
                progress_cb("aggregate", f"Failed: {exc}", state="error")
            return None
    return None


__all__ = [
    "call_gemini_generate",
    "call_model_for_aggregate",
    "call_model_for_file",
    "ensure_gemini_client",
    "try_extract_json_block",
    "wait_for_rate_limit",
]
