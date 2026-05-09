"""
Report generator — renders the Twig/Jinja2 template with scan data.
This module transforms the raw scan results into beautiful HTML and structured JSON.
"""

# Import future type annotations
from __future__ import annotations

import hashlib
import json
import os
import re
import textwrap
from datetime import datetime, timezone

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:  # pragma: no cover - exercised when jinja2 is unavailable
    class FileSystemLoader:
        def __init__(self, *args, **kwargs):
            pass


    class _FallbackTemplate:
        def render(self, **context):
            findings = context.get("active_findings", [])
            errors = context.get("errors", [])
            return (
                "<!doctype html><html><head><meta charset='utf-8'>"
                f"<title>{context.get('plugin_name', 'checkwp')} report</title>"
                "</head><body>"
                f"<h1>{context.get('plugin_name', 'checkwp')}</h1>"
                f"<p>Grade: {context.get('grade', 'N/A')}</p>"
                f"<p>Findings: {len(findings)}</p>"
                f"<p>Errors: {len(errors)}</p>"
                "</body></html>"
            )


    class Environment:
        def __init__(self, *args, **kwargs):
            self.filters = {}

        def get_template(self, template_file):
            return _FallbackTemplate()

from checkwp.scanner.engine import Finding, ScanResult

# Mapping of theme names to their respective Twig template files
THEMES = {
    # The default 'sleek' theme
    "sleek": "theme.twig",
}

# Define the absolute directory where templates are stored
TEMPLATE_DIR = os.path.dirname(__file__)


def _comma_filter(value: int | float) -> str:
    """Jinja2 filter to format numbers with comma thousands-separators."""
    # Convert to int and apply comma formatting
    return f"{int(value):,}"


def _clamp_filter(value: float, min_val: float, max_val: float) -> float:
    """Jinja2 filter to clamp a numerical value between a minimum and maximum."""
    # Calculate clamped value using max and min
    return max(min_val, min(value, max_val))


def _inline_code_filter(text: str) -> str:
    """
    Jinja2 filter to wrap code-like patterns in styled <code> tags.
    Identifies functions, variables, and dangerous PHP/JS keywords.
    """
    # Import regex module
    import re
    # List of regex substitution patterns and their HTML replacements
    patterns = [
        # Match function calls like foo()
        (
            r'(\b[a-zA-Z_]\w*\s*\(\))',
            r'<code class="mono bg-slate-100 px-1 rounded text-rose-600 font-bold text-[0.9em]">\1</code>',
        ),
        # Match PHP variables like $variable
        (
            r'(\$[a-zA-Z_]\w*)',
            r'<code class="mono bg-slate-100 px-1 rounded text-indigo-600 text-[0.9em]">\1</code>',
        ),
        # Match PHP superglobals like $_GET
        (
            r'(\$_(?:GET|POST|REQUEST|SERVER|COOKIE|SESSION))',
            r'<code class="mono bg-slate-100 px-1 rounded text-amber-600 text-[0.9em] font-bold">\1</code>',
        ),
        # Match common security-sensitive or relevant WP functions
        (
            r'(' \
            r'\b(?:eval|system|exec|passthru|shell_exec|assert|create_function|unserialize|'
            r'innerHTML|document\.write|wp_remote_get|wpdb|prepare|sanitize_text_field|'
            r'esc_html|esc_attr)\b' \
            r')',
            r'<code class="mono bg-rose-50 px-1 rounded text-rose-700 font-bold">\1</code>',
        ),
    ]
    # Apply every transformation to the text
    for pattern, replacement in patterns:
        # Perform regex substitution
        text = re.sub(pattern, replacement, text)
    # Return processed string
    return text


def _safe_text(value: str | None) -> str:
    """Return a printable fallback for missing values."""
    return value if value else "unknown"


def _strip_markdown_markup(text: str) -> str:
    """Convert simple markdown fragments into plain text for PDF output."""
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1 (\2)", text)
    text = re.sub(r"[*_#>-]", "", text)
    return text.strip()


def _markdown_report_lines(result: ScanResult) -> list[str]:
    """Build a readable markdown report for downloads."""
    lines: list[str] = [
        f"# Security Report — {result.plugin_name}",
        "",
        f"- **Version:** {_safe_text(result.plugin_version)}",
        f"- **Path:** {result.plugin_path}",
        f"- **Grade:** {result.grade()}",
        f"- **Scan mode:** {result.scan_mode}",
        f"- **Duration:** {result.scan_duration}s",
        "",
        "## Summary",
        f"- Critical: {result.critical_count}",
        f"- High: {result.high_count}",
        f"- Medium: {result.medium_count}",
        f"- Low: {result.low_count}",
        f"- Total findings: {result.total_findings}",
        f"- Files scanned: {len(result.files_scanned)}",
        f"- Lines analyzed: {sum(f.lines for f in result.files_scanned)}",
        "",
    ]

    if result.findings:
        lines.append("## Findings")
        for index, finding in enumerate(result.findings, 1):
            lines.extend(
                [
                    f"### {index}. {finding.pattern.id} — {finding.pattern.title}",
                    f"- Severity: {finding.severity.label}",
                    f"- File: {finding.file_path}:{finding.line_number}:{finding.match_column}",
                    f"- Confidence: {finding.pattern.confidence}",
                    f"- Description: {finding.pattern.description}",
                ]
            )
            impact = getattr(finding.pattern, "impact", "")
            recommendation = getattr(finding.pattern, "recommendation", "")
            if impact:
                lines.append(f"- Impact: {impact}")
            if recommendation:
                lines.append(f"- Recommendation: {recommendation}")
            if finding.line_content:
                lines.append("")
                lines.append("```")
                for ctx_line in finding.context_before:
                    lines.append(ctx_line)
                lines.append(finding.line_content)
                for ctx_line in finding.context_after:
                    lines.append(ctx_line)
                lines.append("```")
            lines.append("")
    else:
        lines.extend(["## Findings", "No findings were detected.", ""])

    if result.files_scanned:
        lines.append("## Files Scanned")
        for fi in result.files_scanned:
            lines.append(f"- `{fi.relative_path}` ({fi.language}, {fi.lines} lines, entropy {fi.entropy:.2f})")
        lines.append("")

    if result.errors:
        lines.append("## Errors")
        for error in result.errors:
            lines.append(f"- {error}")
        lines.append("")

    return lines


def _markdown_report(result: ScanResult) -> str:
    return "\n".join(_markdown_report_lines(result)).rstrip() + "\n"


def _pdf_escape(text: str) -> str:
    text = text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    return text.replace("\r", "")


def _wrap_plain_text(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    return textwrap.wrap(text, width=width, replace_whitespace=False, drop_whitespace=False) or [""]


def _pdf_bytes_from_lines(lines: list[str]) -> bytes:
    """Render a minimal text-only PDF document."""
    page_width = 612
    page_height = 792
    margin = 40
    font_size = 10
    leading = 13
    max_chars = 90

    wrapped: list[str] = []
    for line in lines:
        plain = _strip_markdown_markup(line)
        if plain.startswith("```"):
            plain = ""
        if not plain and line.strip() == "```":
            wrapped.append("")
            continue
        if plain.startswith("# "):
            wrapped.extend(["", plain[2:].upper(), ""])
            continue
        if plain.startswith("## "):
            wrapped.extend(["", plain[3:].upper(), ""])
            continue
        if plain.startswith("### "):
            wrapped.extend(["", plain[4:], ""])
            continue
        wrapped.extend(_wrap_plain_text(plain, max_chars))

    lines_per_page = max(1, int((page_height - 2 * margin) / leading))
    pages = [wrapped[i:i + lines_per_page] for i in range(0, len(wrapped), lines_per_page)] or [[""]]

    pdf_objects: list[tuple[int, bytes]] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b""),
        (3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"),
    ]
    page_objs: list[int] = []
    content_objs: list[int] = []

    for index, page_lines in enumerate(pages, 1):
        page_obj = 4 + ((index - 1) * 2)
        content_obj = page_obj + 1
        page_objs.append(page_obj)
        content_objs.append(content_obj)

        stream_lines = ["BT", f"/F1 {font_size} Tf"]
        y = page_height - margin
        for line in page_lines:
            stream_lines.append(f"1 0 0 1 {margin} {y} Tm")
            stream_lines.append(f"({_pdf_escape(line)}) Tj")
            y -= leading
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
        pdf_objects.append((content_obj, f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"))

    pages_kids = " ".join(f"{obj} 0 R" for obj in page_objs)
    pdf_objects[1] = (
        2,
        f"<< /Type /Pages /Kids [{pages_kids}] /Count {len(page_objs)} >>".encode("ascii"),
    )
    for page_obj, content_obj in zip(page_objs, content_objs):
        pdf_objects.append(
            (
                page_obj,
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_obj} 0 R >>".encode(
                    "ascii"
                ),
            )
        )

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in sorted(pdf_objects, key=lambda item: item[0]):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_start = len(output)
    output.extend(f"xref\n0 {len(pdf_objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(pdf_objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def _write_pdf_report(result: ScanResult, output_path: str | None = None) -> bytes:
    pdf_bytes = _pdf_bytes_from_lines(_markdown_report_lines(result))
    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
    return pdf_bytes


def _detect_language(file_path: str) -> str:
    """Map a file extension to a Prism.js language class for syntax highlighting."""
    # Extract file extension in lowercase
    ext = os.path.splitext(file_path)[1].lower()
    # Return mapped language identifier
    return {
        # PHP files
        ".php": "php", ".inc": "php", ".module": "php",
        # JavaScript files
        ".js":  "javascript", ".jsx": "javascript", ".mjs": "javascript",
        # TypeScript files
        ".ts":  "typescript", ".tsx": "typescript",
    }.get(ext, "markup")  # Default to markup/html


def _build_finding_dict(f: Finding) -> dict:
    """
    Helper function to convert a Finding object into a plain dictionary.
    Used for providing structured context to the Jinja2 template.
    """
    # Extract numeric CWE identifier if present
    cwe_num = f.pattern.cwe.replace("CWE-", "") if f.pattern.cwe else ""
    # Construct the dictionary
    return {
        # Rule identifier
        "rule_id":          f.pattern.id,
        # Human-readable title
        "title":            f.pattern.title,
        # Text severity label
        "severity_label":   f.severity.label,
        # Numeric severity value
        "severity_value":   f.severity.value,
        # Path to file
        "file_path":        f.file_path,
        # Exact line number
        "line_number":      f.line_number,
        # Match start column
        "match_column":     f.match_column,
        # Content of matching line
        "line_content":     f.line_content,
        # Context lines before match
        "context_before":   f.context_before,
        # Context lines after match
        "context_after":    f.context_after,
        # Technical description
        "description":      f.pattern.description,
        # Impact analysis for laypeople
        "impact":           getattr(f.pattern, "impact", ""),
        # Simple fix guide for laypeople
        "layman_fix":       getattr(f.pattern, "layman_fix", ""),
        # Technical checklist for developers
        "step_by_step_fix": getattr(f.pattern, "step_by_step_fix", []),
        # Syntax highlighting language
        "language":         _detect_language(f.file_path),
        # Full CWE identifier
        "cwe":              f.pattern.cwe,
        # Raw CWE number
        "cwe_num":          cwe_num,
        # Confidence score
        "confidence":       f.pattern.confidence,
        # Actionable recommendation
        "recommendation":   f.pattern.recommendation,
        # FP flag
        "false_positive":   f.false_positive,
        # Optional AI text
        "ai_analysis":      f.ai_analysis,
        # Optional AI confirmation
        "ai_confirmed":     f.ai_confirmed,
    }


def generate_html_report(
    result: ScanResult,
    output_path: str | None = None,
    theme: str = "sleek",
    report_assets: dict[str, str] | None = None,
) -> str:
    """
    Renders the scan result into a premium HTML document using Jinja2/Twig.
    Handles data formatting, grade calculation, and template rendering.
    """
    # Initialize Jinja2 environment
    env = Environment(
        # Load from template directory
        loader=FileSystemLoader(TEMPLATE_DIR),
        # Enable HTML auto-escaping
        autoescape=True,
    )
    # Register custom filters
    env.filters["comma"] = _comma_filter
    env.filters["clamp"] = _clamp_filter
    env.filters["inline_code"] = _inline_code_filter

    # Get the theme template file
    template_file = THEMES.get(theme)
    # Fail fast for unsupported themes so callers get a clear error
    if template_file is None:
        # Raise an explicit theme error for unsupported values
        raise ValueError(f"Unknown report theme: {theme}")
    # Load template into memory
    template = env.get_template(template_file)

    # Filter findings into true positives and false positives
    active_findings = [f for f in result.findings if not f.false_positive]
    # Extract FPs
    fp_findings = [f for f in result.findings if f.false_positive]
    # Calculate total lines scanned across all files
    total_lines = sum(f.lines for f in result.files_scanned)

    # Grade dash offset calculation for SVG ring animation
    grade = result.grade()
    # Score map for grading circle
    score_map = {
        "A+": 100, "A": 95, "A-": 90, "B+": 85, "B": 80, "B-": 75,
        "C+": 70, "C": 65, "C-": 60, "D+": 55, "D": 50, "D-": 45, "F": 20,
    }
    # Calculate percentage for progress circle
    score_pct = score_map.get(grade, 0) / 100
    # Calculate SVG stroke-dashoffset
    dash_offset = 352 * (1 - score_pct)

    # Prepare file inventory list for the report
    file_list = []
    # Sort files by path for consistency
    for fi in sorted(result.files_scanned, key=lambda f: f.relative_path):
        # Format size for readability
        size_display = f"{fi.size / 1024:.1f} KB" if fi.size >= 1024 else f"{fi.size} B"
        # Append formatted dict
        file_list.append(
            {
                "relative_path": fi.relative_path,
                "language":      fi.language,
                "size_display":  size_display,
                "lines":         fi.lines,
                "entropy":       fi.entropy,
                "sha256":        fi.sha256,
            }
        )

    # Generate a unique hash for this specific scan execution
    report_id = hashlib.sha256(
        # Hash path + current UTC time
        f"{result.plugin_path}:{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12].upper()  # Truncate for display

    # Build the full context dictionary for the template
    context = {
        # Name of plugin
        "plugin_name":       result.plugin_name,
        # Plugin version discovered from readme.txt
        "plugin_version":    _safe_text(result.plugin_version),
        # Path to source
        "plugin_path":       result.plugin_path,
        # Formatted UTC date
        "scan_date":         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        # Execution mode
        "scan_mode":         result.scan_mode,
        # AI flag
        "ai_enabled":        result.ai_enabled,
        # AI model name
        "ai_model":          result.ai_model,
        # Token usage
        "ai_tokens":         result.ai_tokens,
        # Final unique ID
        "report_id":         f"WPC-{report_id}",
        # Letter grade
        "grade":             grade,
        # Grade color HEX
        "grade_color":       result.grade_color(),
        # SVG circle offset
        "grade_dash_offset": dash_offset,
        # Findings count: Critical
        "critical_count":    result.critical_count,
        # Findings count: High
        "high_count":        result.high_count,
        # Findings count: Medium
        "medium_count":      result.medium_count,
        # Findings count: Low
        "low_count":         result.low_count,
        # Total findings
        "total_findings":    result.total_findings,
        # Count of files
        "files_scanned":     len(result.files_scanned),
        # Total line count
        "total_lines":       total_lines,
        # Performance duration
        "scan_duration":     result.scan_duration,
        # List of finding dicts
        "active_findings":   [_build_finding_dict(f) for f in active_findings],
        # List of FP findings
        "fp_findings":       [_build_finding_dict(f) for f in fp_findings],
        # Full file inventory
        "file_list":         file_list,
        # Optional report download filenames
        "report_assets":     report_assets,
        # Encountered errors
        "errors":            result.errors,
    }

    # Render template with context
    report = template.render(**context)

    # Save to disk if path is provided
    if output_path:
        # Open file for writing
        with open(output_path, "w", encoding="utf-8") as f:
            # Write full HTML string
            f.write(report)

    # Return the HTML string
    return report


def generate_markdown_report(result: ScanResult, output_path: str | None = None) -> str:
    """Render the scan result into a Markdown report."""
    report = _markdown_report(result)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
    return report


def generate_pdf_report(result: ScanResult, output_path: str | None = None) -> bytes:
    """Render the scan result into a simple text-based PDF report."""
    return _write_pdf_report(result, output_path)


def generate_json_report(result: ScanResult) -> str:
    """Converts the scan result into a minified JSON string for CI/CD or API use."""
    # Build a flattened data structure
    data = {
        # Basic metadata
        "plugin_name":   result.plugin_name,
        "plugin_version": _safe_text(result.plugin_version),
        "plugin_path":   result.plugin_path,
        "grade":         result.grade(),
        "scan_mode":     result.scan_mode,
        "ai_enabled":    result.ai_enabled,
        "scan_duration": result.scan_duration,
        # Summary statistics
        "summary":       {
            "total":    result.total_findings,
            "critical": result.critical_count,
            "high":     result.high_count,
            "medium":   result.medium_count,
            "low":      result.low_count,
            "info":     result.info_count,
        },
        # File count
        "files_scanned": len(result.files_scanned),
        # Detailed findings list
        "findings":      [
            {
                # Rule ID
                "id":             f.pattern.id,
                # Rule Title
                "title":          f.pattern.title,
                # Severity text
                "severity":       f.severity.label,
                # File location
                "file":           f.file_path,
                # Line number
                "line":           f.line_number,
                # Matching code
                "code":           f.line_content,
                # CWE ID
                "cwe":            f.pattern.cwe,
                # Explanation
                "description":    f.pattern.description,
                # Potential impact
                "impact":         getattr(f.pattern, "impact", ""),
                # How to fix
                "recommendation": f.pattern.recommendation,
                # FP flag
                "false_positive": f.false_positive,
                # AI Analysis
                "ai_analysis":    f.ai_analysis,
            }
            # Iterate through all findings
            for f in result.findings
        ],
        # Errors log
        "errors":        result.errors,
    }
    # Return as indented JSON string
    return json.dumps(data, indent=2, ensure_ascii=False)
