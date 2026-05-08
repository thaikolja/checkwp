"""Optional LLM-enhanced analysis via OpenAI-compatible API."""

from __future__ import annotations

import os
from typing import List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from checkwp.scanner.engine import Finding, ScanResult

console = Console(stderr=True)

SYSTEM_PROMPT = """You are an expert WordPress security auditor with deep knowledge of PHP, JavaScript, and WordPress internals. You are analyzing findings from an automated vulnerability scanner.

For each finding, you must:
1. Determine if it is a TRUE POSITIVE or FALSE POSITIVE
2. Assess the actual severity in context
3. Provide a brief, actionable explanation (2-3 sentences max)

Respond in this exact format for each finding (one per line):
VERDICT: TRUE_POSITIVE | FALSE_POSITIVE
SEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO
ANALYSIS: <your brief explanation>

Be conservative — if uncertain, lean toward TRUE_POSITIVE. Focus on WordPress-specific context."""


def _build_finding_prompt(finding: Finding, file_content: Optional[str] = None) -> str:
    """Build an analysis prompt for a single finding."""
    ctx_before = "\n".join(finding.context_before) if finding.context_before else "(no context)"
    ctx_after = "\n".join(finding.context_after) if finding.context_after else "(no context)"

    prompt = f"""Analyze this potential vulnerability:

**Rule**: {finding.pattern.id} — {finding.pattern.title}
**Severity**: {finding.pattern.severity.label}
**File**: {finding.file_path} (line {finding.line_number})
**CWE**: {finding.pattern.cwe}
**Description**: {finding.pattern.description}

**Code Context**:
```
{ctx_before}
>>> {finding.line_content}
{ctx_after}
```
"""
    if file_content:
        # Send up to 200 lines around the finding for deeper context
        lines = file_content.splitlines()
        start = max(0, finding.line_number - 50)
        end = min(len(lines), finding.line_number + 50)
        broader = "\n".join(lines[start:end])
        prompt += f"\n**Broader File Context** (lines {start+1}-{end}):\n```\n{broader}\n```\n"

    return prompt


def _batch_findings(findings: List[Finding], batch_size: int = 5) -> list[list[Finding]]:
    """Split findings into batches for efficient API usage."""
    return [findings[i:i + batch_size] for i in range(0, len(findings), batch_size)]


def _build_batch_prompt(batch: List[Finding]) -> str:
    """Build a single prompt for a batch of findings."""
    parts = []
    for i, f in enumerate(batch, 1):
        ctx_before = "\n".join(f.context_before) if f.context_before else ""
        ctx_after = "\n".join(f.context_after) if f.context_after else ""
        parts.append(
            f"--- FINDING {i} ---\n"
            f"Rule: {f.pattern.id} — {f.pattern.title}\n"
            f"Severity: {f.pattern.severity.label}\n"
            f"File: {f.file_path}:{f.line_number}\n"
            f"CWE: {f.pattern.cwe}\n"
            f"Description: {f.pattern.description}\n"
            f"Code:\n```\n{ctx_before}\n>>> {f.line_content}\n{ctx_after}\n```\n"
        )
    header = f"Analyze these {len(batch)} findings. For EACH finding, respond with:\n"
    header += "FINDING <number>:\nVERDICT: TRUE_POSITIVE | FALSE_POSITIVE\nSEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO\nANALYSIS: <explanation>\n\n"
    return header + "\n".join(parts)


def _parse_batch_response(response: str, batch: List[Finding]) -> None:
    """Parse the LLM response and annotate findings."""
    import re

    blocks = re.split(r'FINDING\s+\d+\s*:', response, flags=re.IGNORECASE)
    blocks = [b.strip() for b in blocks if b.strip()]

    for i, finding in enumerate(batch):
        if i >= len(blocks):
            finding.ai_analysis = "AI analysis unavailable for this finding."
            continue

        block = blocks[i]

        verdict_m = re.search(r'VERDICT\s*:\s*(TRUE_POSITIVE|FALSE_POSITIVE)', block, re.IGNORECASE)
        severity_m = re.search(r'SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)', block, re.IGNORECASE)
        analysis_m = re.search(r'ANALYSIS\s*:\s*(.+?)(?:\n|$)', block, re.IGNORECASE | re.DOTALL)

        if verdict_m:
            finding.ai_confirmed = verdict_m.group(1).upper() == "TRUE_POSITIVE"
            if not finding.ai_confirmed:
                finding.false_positive = True

        finding.ai_analysis = analysis_m.group(1).strip() if analysis_m else block[:200]


class AIAnalyzer:
    """LLM-powered vulnerability analysis."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ):
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("openai package is required for AI analysis. Install with: pip install openai")

        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _chat(self, user_prompt: str) -> str:
        """Send a chat completion request."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content or ""

    def analyze_findings(self, result: ScanResult, file_contents: dict[str, str] | None = None) -> ScanResult:
        """Analyze all findings with AI assistance."""
        active = [f for f in result.findings if not f.false_positive]
        if not active:
            return result

        batches = _batch_findings(active, batch_size=5)
        total = len(batches)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]AI analysis...[/] {task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("", total=total)
            for i, batch in enumerate(batches):
                progress.update(task, description=f"Batch {i+1}/{total} ({len(batch)} findings)")
                try:
                    prompt = _build_batch_prompt(batch)
                    response = self._chat(prompt)
                    _parse_batch_response(response, batch)
                except Exception as exc:
                    for f in batch:
                        f.ai_analysis = f"AI error: {exc}"
                progress.advance(task)

        result.ai_enabled = True
        return result
