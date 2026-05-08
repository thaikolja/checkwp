"""Professional HTML report generator with TailwindCSS CDN."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Optional

from checktwp.scanner.engine import ScanResult, Finding
from checktwp.scanner.patterns import Severity


def _esc(text: str) -> str:
    return html.escape(str(text))


def _severity_badge(sev: Severity) -> str:
    colors = {
        Severity.CRITICAL: "bg-red-600 text-white",
        Severity.HIGH: "bg-orange-500 text-white",
        Severity.MEDIUM: "bg-amber-500 text-white",
        Severity.LOW: "bg-blue-500 text-white",
        Severity.INFO: "bg-gray-400 text-white",
    }
    cls = colors.get(sev, "bg-gray-400 text-white")
    return f'<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold {cls}">{sev.label}</span>'


def _grade_section(result: ScanResult) -> str:
    grade = result.grade()
    color = result.grade_color()
    return f"""
    <div class="flex items-center justify-center">
      <div class="relative w-40 h-40">
        <svg class="w-40 h-40 transform -rotate-90" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r="70" stroke="#1e293b" stroke-width="12" fill="none"/>
          <circle cx="80" cy="80" r="70" stroke="{color}" stroke-width="12" fill="none"
                  stroke-dasharray="440" stroke-dashoffset="0" stroke-linecap="round"
                  class="transition-all duration-1000"/>
        </svg>
        <div class="absolute inset-0 flex items-center justify-center">
          <span class="text-5xl font-black" style="color:{color}">{grade}</span>
        </div>
      </div>
    </div>"""


def _stat_card(label: str, value: int | str, color: str, icon: str) -> str:
    return f"""
    <div class="bg-slate-800/50 backdrop-blur border border-slate-700/50 rounded-2xl p-5 text-center hover:border-slate-600 transition-colors">
      <div class="text-3xl mb-2">{icon}</div>
      <div class="text-3xl font-bold" style="color:{color}">{value}</div>
      <div class="text-slate-400 text-sm mt-1 font-medium">{label}</div>
    </div>"""


def _finding_row(finding: Finding, index: int) -> str:
    badge = _severity_badge(finding.severity)
    fp_cls = ' opacity-40 line-through' if finding.false_positive else ''

    code_lines = []
    for cl in finding.context_before:
        code_lines.append(f'<span class="text-slate-500">{_esc(cl)}</span>')
    code_lines.append(f'<span class="text-red-400 font-bold bg-red-950/30 block px-1 -mx-1 rounded">{_esc(finding.line_content)}</span>')
    for cl in finding.context_after:
        code_lines.append(f'<span class="text-slate-500">{_esc(cl)}</span>')
    code_block = "\n".join(code_lines)

    ai_section = ""
    if finding.ai_analysis:
        verdict_cls = "text-green-400" if finding.ai_confirmed else "text-yellow-400"
        verdict_txt = "Confirmed" if finding.ai_confirmed else ("False Positive" if finding.ai_confirmed is False else "Uncertain")
        ai_section = f"""
        <div class="mt-3 p-3 bg-indigo-950/30 border border-indigo-800/30 rounded-lg">
          <div class="flex items-center gap-2 mb-1">
            <span class="text-indigo-400 text-xs font-bold uppercase tracking-wider">🤖 AI Analysis</span>
            <span class="{verdict_cls} text-xs font-bold">({verdict_txt})</span>
          </div>
          <p class="text-slate-300 text-sm">{_esc(finding.ai_analysis)}</p>
        </div>"""

    return f"""
    <details class="group border border-slate-700/50 rounded-xl overflow-hidden hover:border-slate-600 transition-colors{fp_cls}" {"open" if finding.severity >= Severity.HIGH and not finding.false_positive else ""}>
      <summary class="flex items-center gap-3 p-4 cursor-pointer bg-slate-800/30 hover:bg-slate-800/50 transition-colors">
        <span class="text-slate-500 font-mono text-sm w-8">#{index}</span>
        {badge}
        <span class="font-semibold text-slate-200 flex-1">{_esc(finding.pattern.title)}</span>
        <span class="text-slate-400 text-sm font-mono">{_esc(finding.file_path)}:{finding.line_number}</span>
        <svg class="w-5 h-5 text-slate-500 group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
        </svg>
      </summary>
      <div class="p-4 border-t border-slate-700/30 space-y-3">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
          <div><span class="text-slate-500">Rule ID:</span> <span class="text-slate-300 font-mono">{_esc(finding.pattern.id)}</span></div>
          <div><span class="text-slate-500">CWE:</span> <a href="https://cwe.mitre.org/data/definitions/{_esc(finding.pattern.cwe.replace('CWE-',''))}.html" target="_blank" class="text-cyan-400 hover:underline">{_esc(finding.pattern.cwe)}</a></div>
          <div><span class="text-slate-500">Confidence:</span> <span class="text-slate-300 capitalize">{_esc(finding.pattern.confidence)}</span></div>
          <div><span class="text-slate-500">Status:</span> <span class="{'text-red-400' if not finding.false_positive else 'text-green-400'}">{'Active' if not finding.false_positive else 'False Positive'}</span></div>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-slate-400 mb-1">Description</h4>
          <p class="text-slate-300 text-sm">{_esc(finding.pattern.description)}</p>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-slate-400 mb-1">Code</h4>
          <pre class="bg-slate-950 border border-slate-700/50 rounded-lg p-3 text-xs font-mono overflow-x-auto leading-relaxed">{code_block}</pre>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-slate-400 mb-1">Recommendation</h4>
          <p class="text-emerald-400 text-sm">{_esc(finding.pattern.recommendation)}</p>
        </div>
        {ai_section}
      </div>
    </details>"""


def _files_table(result: ScanResult) -> str:
    rows = []
    for fi in sorted(result.files_scanned, key=lambda f: f.relative_path):
        size = f"{fi.size / 1024:.1f} KB" if fi.size >= 1024 else f"{fi.size} B"
        entropy_cls = "text-red-400" if fi.entropy > 6.0 else ("text-yellow-400" if fi.entropy > 5.0 else "text-green-400")
        rows.append(f"""
          <tr class="border-b border-slate-700/30 hover:bg-slate-800/30">
            <td class="py-2 px-3 font-mono text-sm text-slate-300">{_esc(fi.relative_path)}</td>
            <td class="py-2 px-3 text-sm text-slate-400">{fi.language}</td>
            <td class="py-2 px-3 text-sm text-slate-400">{size}</td>
            <td class="py-2 px-3 text-sm text-slate-400">{fi.lines:,}</td>
            <td class="py-2 px-3 text-sm font-mono {entropy_cls}">{fi.entropy:.2f}</td>
            <td class="py-2 px-3 text-xs font-mono text-slate-500">{fi.sha256[:16]}…</td>
          </tr>""")
    return "\n".join(rows)


def generate_html_report(result: ScanResult, output_path: Optional[str] = None) -> str:
    """Generate a professional HTML security report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    active_findings = [f for f in result.findings if not f.false_positive]
    fp_findings = [f for f in result.findings if f.false_positive]
    total_lines = sum(f.lines for f in result.files_scanned)

    # Build findings HTML
    findings_html = []
    for i, f in enumerate(active_findings, 1):
        findings_html.append(_finding_row(f, i))

    fp_html = []
    if fp_findings:
        for i, f in enumerate(fp_findings, 1):
            fp_html.append(_finding_row(f, i))

    report = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report — {_esc(result.plugin_name)} | checktwp</title>
  <meta name="description" content="WordPress Plugin Security Report for {_esc(result.plugin_name)} generated by checktwp">
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    * {{ font-family: 'Inter', system-ui, sans-serif; }}
    code, pre, .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    body {{ background: #0b1120; }}
    .gradient-border {{ background: linear-gradient(135deg, #6366f1, #8b5cf6, #a855f7); padding: 1px; border-radius: 1rem; }}
    .gradient-border > div {{ background: #0f172a; border-radius: calc(1rem - 1px); }}
    .glow {{ box-shadow: 0 0 40px -10px rgba(99, 102, 241, 0.3); }}
    @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
    .animate-in {{ animation: fadeIn 0.5s ease-out forwards; }}
    details[open] summary {{ border-bottom: 1px solid rgb(51, 65, 85, 0.3); }}
    @media print {{
      body {{ background: white; color: black; }}
      details {{ display: block !important; }}
      details > summary {{ display: none; }}
      details > div {{ display: block !important; }}
    }}
  </style>
</head>
<body class="min-h-screen text-slate-200">
  <!-- Header -->
  <header class="border-b border-slate-800 bg-slate-900/50 backdrop-blur-xl sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white font-black text-lg">⚡</div>
        <div>
          <h1 class="text-lg font-bold text-white">checktwp</h1>
          <p class="text-xs text-slate-500">WordPress Plugin Security Checker</p>
        </div>
      </div>
      <div class="text-right">
        <p class="text-sm text-slate-400">{now}</p>
        <p class="text-xs text-slate-500">Scan Mode: <span class="text-slate-300 capitalize">{result.scan_mode}</span>
           {' • <span class="text-indigo-400">AI Enhanced</span>' if result.ai_enabled else ''}</p>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-6 py-10 space-y-10">
    <!-- Plugin Info & Grade -->
    <section class="animate-in">
      <div class="gradient-border glow">
        <div class="p-8">
          <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
            <div class="lg:col-span-2">
              <p class="text-sm text-indigo-400 font-semibold uppercase tracking-wider mb-2">Security Assessment</p>
              <h2 class="text-4xl font-black text-white mb-3">{_esc(result.plugin_name)}</h2>
              <p class="text-slate-400 text-sm font-mono mb-4">{_esc(result.plugin_path)}</p>
              <div class="flex flex-wrap gap-4 text-sm">
                <span class="text-slate-400">{len(result.files_scanned)} files scanned</span>
                <span class="text-slate-600">•</span>
                <span class="text-slate-400">{total_lines:,} lines analyzed</span>
                <span class="text-slate-600">•</span>
                <span class="text-slate-400">{result.scan_duration}s duration</span>
                <span class="text-slate-600">•</span>
                <span class="text-slate-400">{result.total_findings} findings</span>
              </div>
            </div>
            <div>
              {_grade_section(result)}
              <p class="text-center text-sm text-slate-400 mt-3">Security Grade</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Stats Cards -->
    <section class="animate-in" style="animation-delay: 0.1s">
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
        {_stat_card("Critical", result.critical_count, "#dc2626", "🔴")}
        {_stat_card("High", result.high_count, "#ea580c", "🟠")}
        {_stat_card("Medium", result.medium_count, "#d97706", "🟡")}
        {_stat_card("Low", result.low_count, "#2563eb", "🔵")}
        {_stat_card("Info", result.info_count, "#6b7280", "⚪")}
      </div>
    </section>

    <!-- Findings -->
    <section class="animate-in" style="animation-delay: 0.2s">
      <div class="flex items-center justify-between mb-6">
        <h3 class="text-2xl font-bold text-white">Vulnerability Findings</h3>
        <span class="text-sm text-slate-500">{len(active_findings)} active findings{f' • {len(fp_findings)} false positives' if fp_findings else ''}</span>
      </div>
      <div class="space-y-3">
        {"".join(findings_html) if findings_html else '<div class="text-center py-16 text-slate-500"><div class="text-5xl mb-4">🛡️</div><p class="text-xl font-semibold text-green-400">No vulnerabilities detected</p><p class="mt-2">This plugin passed all automated security checks.</p></div>'}
      </div>
    </section>

    {"" if not fp_html else f'''
    <!-- False Positives -->
    <section class="animate-in" style="animation-delay: 0.3s">
      <details class="group">
        <summary class="flex items-center gap-2 cursor-pointer mb-4">
          <h3 class="text-xl font-bold text-slate-500">Dismissed / False Positives</h3>
          <span class="text-sm text-slate-600">({len(fp_findings)})</span>
          <svg class="w-5 h-5 text-slate-600 group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
          </svg>
        </summary>
        <div class="space-y-3">
          {"".join(fp_html)}
        </div>
      </details>
    </section>
    '''}

    <!-- Files Scanned -->
    <section class="animate-in" style="animation-delay: 0.4s">
      <details>
        <summary class="flex items-center gap-2 cursor-pointer mb-4">
          <h3 class="text-xl font-bold text-white">Scanned Files</h3>
          <span class="text-sm text-slate-500">({len(result.files_scanned)} files)</span>
          <svg class="w-5 h-5 text-slate-500 group-open:rotate-180 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
          </svg>
        </summary>
        <div class="overflow-x-auto bg-slate-800/30 rounded-xl border border-slate-700/50">
          <table class="w-full">
            <thead>
              <tr class="border-b border-slate-700/50 text-left">
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">File</th>
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">Language</th>
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">Size</th>
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">Lines</th>
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">Entropy</th>
                <th class="py-3 px-3 text-xs font-bold text-slate-400 uppercase tracking-wider">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {_files_table(result)}
            </tbody>
          </table>
        </div>
      </details>
    </section>

    {f'''
    <!-- Errors -->
    <section class="animate-in">
      <div class="bg-red-950/20 border border-red-800/30 rounded-xl p-4">
        <h3 class="text-lg font-bold text-red-400 mb-2">Scan Errors</h3>
        <ul class="space-y-1 text-sm text-red-300">
          {"".join(f"<li>• {_esc(e)}</li>" for e in result.errors)}
        </ul>
      </div>
    </section>
    ''' if result.errors else ''}
  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800 mt-16">
    <div class="max-w-7xl mx-auto px-6 py-8 text-center text-sm text-slate-500">
      <p>Generated by <strong class="text-slate-400">checktwp</strong> — WordPress Plugin Security Checker v1.0.0</p>
      <p class="mt-1">This is an automated report. Manual code review is always recommended for production plugins.</p>
    </div>
  </footer>
</body>
</html>"""

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
                "recommendation": f.pattern.recommendation,
                "false_positive": f.false_positive,
                "ai_analysis": f.ai_analysis,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
