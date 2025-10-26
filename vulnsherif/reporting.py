"""Utilities for building reports and frontend payloads."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .config import AGGREGATE_CONTENT_PREVIEW_CHARS
from .text_utils import clamp_characters, coerce_text, truncate_words

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


def sanitize_instruction(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    title = coerce_text(raw.get("title"))
    steps_raw = raw.get("steps") or raw.get("instructions") or []
    if isinstance(steps_raw, str):
        steps_iterable = [steps_raw]
    elif isinstance(steps_raw, list):
        steps_iterable = steps_raw
    else:
        steps_iterable = []
    steps: List[str] = []
    for step in steps_iterable:
        text = coerce_text(step)
        if text:
            steps.append(text)
    note = coerce_text(raw.get("note"))
    return {
        "title": title,
        "steps": steps,
        "note": note,
    }


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

    raw_instructions = (
        raw_payload.get("instruction") or raw_payload.get("instructions") or []
    )
    instructions: List[Dict[str, Any]] = []
    if isinstance(raw_instructions, list):
        for item in raw_instructions:
            sanitized_instruction = sanitize_instruction(item)
            if sanitized_instruction:
                instructions.append(sanitized_instruction)

    summary = coerce_text(raw_payload.get("summary") or fallback_summary)
    return {"summary": summary, "findings": findings, "instructions": instructions}


def parse_cvss_score(value: Any) -> Tuple[str, Optional[float]]:
    raw_text = coerce_text(value)
    if not raw_text:
        return "N/A", None
    import re

    match = re.search(r"\d+(?:\.\d+)?", raw_text)
    if not match:
        return raw_text, None
    try:
        score = float(match.group())
    except ValueError:
        return raw_text, None
    score = max(0.0, min(score, 10.0))
    return f"{score:.1f}", score


def determine_star_rating(severity: str, cvss_value: Optional[float]) -> int:
    if cvss_value is not None:
        if cvss_value >= 9.0:
            return 5
        if cvss_value >= 7.0:
            return 4
        if cvss_value >= 4.0:
            return 3
        if cvss_value >= 1.0:
            return 2
        return 1
    severity_scale = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
    }
    return severity_scale.get(severity, 1)


def build_star_display(stars: int, total: int = 5) -> str:
    stars = max(0, min(stars, total))
    return "★" * stars + "☆" * (total - stars)


def prepare_finding_card(raw: Dict[str, Any]) -> Dict[str, Any]:
    severity = normalize_severity(raw.get("severity"))
    title = coerce_text(raw.get("title") or "Untitled Finding")
    description = clamp_characters(coerce_text(raw.get("description")), 200)
    if not description:
        description = "No description provided."
    suggestion_source = raw.get("suggestion") or raw.get("remediation")
    suggestion = clamp_characters(coerce_text(suggestion_source), 200)
    if not suggestion:
        suggestion = "No remediation guidance provided."
    cvss_text, cvss_value = parse_cvss_score(raw.get("cvss_score") or raw.get("cvss"))
    star_rating = determine_star_rating(severity, cvss_value)
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "suggestion": suggestion,
        "cvss_score": cvss_text,
        "star_rating": star_rating,
        "star_display": build_star_display(star_rating),
        "star_label": f"{star_rating} out of 5",
    }


def build_overall_summary(
    scan_meta: Optional[Dict[str, Any]],
    severity_counts: Optional[Dict[str, int]],
    summary_text: str,
    status_message: str,
) -> str:
    scan_meta = scan_meta or {}
    files_included = scan_meta.get("files_included") or 0
    notes_provided = bool(scan_meta.get("notes_provided"))
    prompt_only = bool(scan_meta.get("prompt_only"))
    notes_only = bool(scan_meta.get("notes_only"))

    total_findings = 0
    highest_severity: Optional[str] = None
    if severity_counts:
        for label in SEVERITY_LABELS:
            count = severity_counts.get(label, 0)
            total_findings += count
            if highest_severity is None and count > 0:
                highest_severity = label

    context_parts: List[str] = []
    if files_included:
        plural = "s" if files_included != 1 else ""
        context_parts.append(f"Scanned {files_included} file{plural}.")
    elif notes_provided or prompt_only or notes_only:
        context_parts.append("No files were uploaded; the assessment is based on the provided notes.")
    else:
        context_parts.append(
            "No source code was provided for analysis. The audit could not be performed, and therefore "
            "no security findings can be reported. Please provide the contents of the relevant files "
            "for a complete security review."
        )

    if total_findings == 0:
        risk_summary = "No structured vulnerabilities were reported in the current scan."
    else:
        severity_phrases = {
            "Critical": "Severe risk: critical issues need immediate attention.",
            "High": "High risk: significant weaknesses were detected.",
            "Medium": "Moderate risk: issues should be addressed promptly.",
            "Low": "Low risk: minor findings were recorded.",
        }
        severity_text = severity_phrases.get(highest_severity, "Risk level undetermined.")
        highest_count = severity_counts.get(highest_severity, 0) if severity_counts else 0
        risk_summary = (
            f"{severity_text} Detected {total_findings} total finding"
            f"{'s' if total_findings != 1 else ''}, including "
            f"{highest_count} {highest_severity.lower() if highest_severity else 'unknown'} severity item"
            f"{'s' if highest_count != 1 else ''}."
        )

    summary_components = context_parts + [risk_summary]

    summary_body = summary_text.strip() if summary_text else ""
    if summary_body:
        summary_components.append(summary_body)
    if status_message and status_message not in summary_components:
        summary_components.append(status_message)

    combined = " ".join(part.strip() for part in summary_components if part)
    if not combined:
        return (
            "No source code was provided for analysis. The audit could not be performed, and therefore "
            "no security findings can be reported. Please provide the contents of the relevant files "
            "for a complete security review."
        )
    return combined


def build_frontend_payload(job_result: Dict[str, Any]) -> Dict[str, Any]:
    report = job_result.get("report") or {}
    scan_meta = job_result.get("scan_meta") or {}
    prompt_only_mode = bool(scan_meta.get("prompt_only") or scan_meta.get("notes_only"))
    instructions = report.get("instructions") or []
    if not isinstance(instructions, list):
        instructions = []
    primary_instruction = instructions[0] if instructions else {}
    raw_findings = report.get("findings") or []
    prepared_findings: List[Dict[str, Any]] = []
    for raw in raw_findings:
        prepared_findings.append(prepare_finding_card(raw))
    if not prepared_findings and not prompt_only_mode:
        summary_text = coerce_text(report.get("summary")) or coerce_text(
            job_result.get("status_message")
        )
        prepared_findings.append(
            prepare_finding_card(
                {
                    "title": "No Vulnerabilities Reported",
                    "severity": "Low",
                    "description": summary_text
                    or "The analysis completed without returning structured findings.",
                    "remediation": "If you expected findings, consider rerunning the scan with additional context or files.",
                    "cvss_score": "N/A",
                }
            )
        )
    severity_counts = job_result.get("severity_counts") or {}
    summary_raw = coerce_text(report.get("summary"))
    summary_text = truncate_words(summary_raw, 80)
    status_raw = coerce_text(job_result.get("status_message"))
    status_message = truncate_words(status_raw, 40)
    overall_summary = build_overall_summary(
        scan_meta, severity_counts, summary_text, status_message
    )

    def _normalize(text: str) -> str:
        return " ".join(text.lower().split())

    normalized_overall = _normalize(overall_summary)
    if summary_text and _normalize(summary_text) in normalized_overall:
        summary_text = ""
    if status_message:
        norm_status = _normalize(status_message)
        if norm_status in normalized_overall or (
            summary_text and norm_status in _normalize(summary_text)
        ):
            status_message = ""
        elif summary_text and status_message == summary_text:
            status_message = ""
    return {
        "findings": prepared_findings,
        "summary": summary_text,
        "overall_summary": overall_summary,
        "scan_meta": scan_meta,
        "severity_counts": severity_counts,
        "status_message": status_message,
        "raw_report": report,
        "prompt_only": prompt_only_mode,
        "instructions": instructions,
        "instruction": primary_instruction,
    }


def build_frontend_error_payload(message: str, severity: str = "High") -> Dict[str, Any]:
    safe_message = coerce_text(message) or "Analysis failed unexpectedly."
    summary_trimmed = truncate_words(safe_message, 80)
    finding = prepare_finding_card(
        {
            "title": "Analysis Failed",
            "severity": severity,
            "description": safe_message,
            "remediation": "Please try again later or adjust your input files and resubmit.",
            "cvss_score": "N/A",
        }
    )
    return {
        "findings": [finding],
        "summary": summary_trimmed,
        "overall_summary": summary_trimmed,
        "scan_meta": None,
        "severity_counts": None,
        "status_message": summary_trimmed,
        "raw_report": None,
        "prompt_only": False,
        "instructions": [],
        "instruction": {},
    }


__all__ = [
    "AGGREGATE_CONTENT_PREVIEW_CHARS",
    "SEVERITY_LABELS",
    "build_frontend_error_payload",
    "build_frontend_payload",
    "build_report",
    "build_overall_summary",
    "normalize_severity",
    "sanitize_finding",
    "sanitize_instruction",
]
