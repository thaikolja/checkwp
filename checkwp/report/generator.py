"""Report generator — renders the Twig/Jinja2 template with scan data."""

from __future__ import annotations

import hashlib
import html
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

THEMES = {
    "sleek": "report-sleek.html.twig",
}

from jinja2 import Environment, FileSystemLoader

from checkwp.scanner.engine import ScanResult, Finding
from checkwp.scanner.patterns import Severity


TEMPLATE_DIR = os.path.dirname(__file__)


def _comma_filter(value: int | float) -> str:
    """Format numbers with comma separators."""
    return f"{int(value):,}"


def _clamp_filter(value: float, min_val: float, max_val: float) -> float:
    """Clamp a value between min and max."""
    return max(min_val, min(value, max_val))


def _inline_code_filter(text: str) -> str:
    """Wrap functions, variables, and common code patterns in <code> tags."""
    import re
    # Patterns for functions(), $variables, $_GET, and common PHP/JS identifiers
    # We use a broader identifier match for functions to catch more WP-specific ones
    patterns = [
        (r'(\b[a-zA-Z_]\w*\s*\(\))', r'<code class="mono bg-slate-100 px-1 rounded text-rose-600 font-bold text-[0.9em]">\1</code>'),
        (r'(\$[a-zA-Z_]\w*)', r'<code class="mono bg-slate-100 px-1 rounded text-indigo-600 text-[0.9em]">\1</code>'),
        (r'(\$_(?:GET|POST|REQUEST|SERVER|COOKIE|SESSION))', r'<code class="mono bg-slate-100 px-1 rounded text-amber-600 text-[0.9em] font-bold">\1</code>'),
        (r'(\b(?:eval|system|exec|passthru|shell_exec|assert|create_function|unserialize|innerHTML|document\.write|wp_remote_get|wpdb|prepare|sanitize_text_field|esc_html|esc_attr)\b)', r'<code class="mono bg-rose-50 px-1 rounded text-rose-700 font-bold">\1</code>'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def _detect_language(file_path: str) -> str:
    """Map file extension to Prism.js language class."""
    ext = os.path.splitext(file_path)[1].lower()
    return {
        ".php": "php", ".inc": "php", ".module": "php",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
    }.get(ext, "markup")


def _build_finding_dict(f: Finding) -> dict:
    """Convert a Finding into a template-friendly dict."""
    cwe_num = f.pattern.cwe.replace("CWE-", "") if f.pattern.cwe else ""
    return {
        "rule_id": f.pattern.id,
        "title": f.pattern.title,
        "severity_label": f.severity.label,
        "severity_value": f.severity.value,
        "file_path": f.file_path,
        "line_number": f.line_number,
        "line_content": f.line_content,
        "context_before": f.context_before,
        "context_after": f.context_after,
        "description": f.pattern.description,
        "impact": getattr(f.pattern, "impact", ""),
        "layman_fix": getattr(f.pattern, "layman_fix", ""),
        "step_by_step_fix": getattr(f.pattern, "step_by_step_fix", []),
        "language": _detect_language(f.file_path),
        "cwe": f.pattern.cwe,
        "cwe_num": cwe_num,
        "confidence": f.pattern.confidence,
        "recommendation": f.pattern.recommendation,
        "false_positive": f.false_positive,
        "ai_analysis": f.ai_analysis,
        "ai_confirmed": f.ai_confirmed,
    }


def generate_html_report(
    result: ScanResult,
    output_path: Optional[str] = None,
    theme: str = "sleek",
) -> str:
    """Generate a professional HTML security report using the Sleek template.

    Args:
        result: Scan results to render.
        output_path: Path to write the HTML file.
        theme: Template theme — 'sleek' is currently the only supported theme.
    """
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
    )
    env.filters["comma"] = _comma_filter
    env.filters["clamp"] = _clamp_filter
    env.filters["inline_code"] = _inline_code_filter

    template_file = THEMES["sleek"]
    template = env.get_template(template_file)

    active_findings = [f for f in result.findings if not f.false_positive]
    fp_findings = [f for f in result.findings if f.false_positive]
    total_lines = sum(f.lines for f in result.files_scanned)

    # Grade dash offset for SVG ring (352 = circumference of r=56)
    grade = result.grade()
    score_map = {
        "A+": 100, "A": 95, "A-": 90, "B+": 85, "B": 80, "B-": 75,
        "C+": 70, "C": 65, "C-": 60, "D+": 55, "D": 50, "D-": 45, "F": 20,
    }
    score_pct = score_map.get(grade, 0) / 100
    dash_offset = 352 * (1 - score_pct)

    # File list for template
    file_list = []
    for fi in sorted(result.files_scanned, key=lambda f: f.relative_path):
        size_display = f"{fi.size / 1024:.1f} KB" if fi.size >= 1024 else f"{fi.size} B"
        file_list.append({
            "relative_path": fi.relative_path,
            "language": fi.language,
            "size_display": size_display,
            "lines": fi.lines,
            "entropy": fi.entropy,
            "sha256": fi.sha256,
        })

    # Generate a deterministic report ID from plugin path + timestamp
    report_id = hashlib.sha256(
        f"{result.plugin_path}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12].upper()

    context = {
        "plugin_name": result.plugin_name,
        "plugin_path": result.plugin_path,
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_mode": result.scan_mode,
        "ai_enabled": result.ai_enabled,
        "report_id": f"CTWP-{report_id}",
        "grade": grade,
        "grade_color": result.grade_color(),
        "grade_dash_offset": dash_offset,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "info_count": result.info_count,
        "total_findings": result.total_findings,
        "files_scanned": len(result.files_scanned),
        "total_lines": total_lines,
        "scan_duration": result.scan_duration,
        "active_findings": [_build_finding_dict(f) for f in active_findings],
        "fp_findings": [_build_finding_dict(f) for f in fp_findings],
        "file_list": file_list,
        "errors": result.errors,
    }

    report = template.render(**context)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    return report


def generate_json_report(result: ScanResult) -> str:
    """Generate a JSON report for programmatic consumption."""
    data = {
        "plugin_name": result.plugin_name,
        "plugin_path": result.plugin_path,
        "grade": result.grade(),
        "scan_mode": result.scan_mode,
        "ai_enabled": result.ai_enabled,
        "scan_duration": result.scan_duration,
        "summary": {
            "total": result.total_findings,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "files_scanned": len(result.files_scanned),
        "findings": [
            {
                "id": f.pattern.id,
                "title": f.pattern.title,
                "severity": f.severity.label,
                "file": f.file_path,
                "line": f.line_number,
                "code": f.line_content,
                "cwe": f.pattern.cwe,
                "description": f.pattern.description,
                "impact": getattr(f.pattern, "impact", ""),
                "recommendation": f.pattern.recommendation,
                "false_positive": f.false_positive,
                "ai_analysis": f.ai_analysis,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
