"""
Optional LLM-enhanced analysis via OpenAI-compatible API.
This module uses artificial intelligence to verify scan findings and reduce false positives.
"""

# Enable future type annotations
from __future__ import annotations

# Import os for environment management
import os
# Import typing for structural hints
from typing import List, Optional

# Import rich for terminal status and progress bars
from rich.console import Console
# Import progress bar components
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import models from the scanner engine
from checkwp.scanner.engine import Finding, ScanResult

# Initialize local console for status messages
console = Console(stderr=True)

# Define the persona and instructions for the AI auditor
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
    """Constructs a detailed text prompt describing a single security finding for the AI."""
    # Format code context before the finding
    ctx_before = "\n".join(finding.context_before) if finding.context_before else "(no context)"
    # Format code context after the finding
    ctx_after = "\n".join(finding.context_after) if finding.context_after else "(no context)"

    # Build the core prompt string
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
    # Append broader file content if provided for deeper analysis
    if file_content:
        # Split content into lines
        lines = file_content.splitlines()
        # Define window start
        start = max(0, finding.line_number - 50)
        # Define window end
        end = min(len(lines), finding.line_number + 50)
        # Extract lines
        broader = "\n".join(lines[start:end])
        # Add to prompt
        prompt += f"\n**Broader File Context** (lines {start+1}-{end}):\n```\n{broader}\n```\n"

    # Return the completed prompt
    return prompt


def _batch_findings(findings: List[Finding], batch_size: int = 5) -> list[list[Finding]]:
    """Partitions a list of findings into smaller groups to optimize API requests and cost."""
    # List comprehension to slice the findings list
    return [findings[i:i + batch_size] for i in range(0, len(findings), batch_size)]


def _build_batch_prompt(batch: List[Finding]) -> str:
    """Aggregates multiple findings into a single consolidated prompt for batch processing."""
    # List to store individual finding descriptions
    parts = []
    # Iterate through findings in the batch
    for i, f in enumerate(batch, 1):
        # Format before context
        ctx_before = "\n".join(f.context_before) if f.context_before else ""
        # Format after context
        ctx_after = "\n".join(f.context_after) if f.context_after else ""
        # Append formatted finding text
        parts.append(
            f"--- FINDING {i} ---\n"
            f"Rule: {f.pattern.id} — {f.pattern.title}\n"
            f"Severity: {f.pattern.severity.label}\n"
            f"File: {f.file_path}:{f.line_number}\n"
            f"CWE: {f.pattern.cwe}\n"
            f"Description: {f.pattern.description}\n"
            f"Code:\n```\n{ctx_before}\n>>> {f.line_content}\n{ctx_after}\n```\n"
        )
    # Define instructions header
    header = f"Analyze these {len(batch)} findings. For EACH finding, respond with:\n"
    # Append required format example
    header += "FINDING <number>:\nVERDICT: TRUE_POSITIVE | FALSE_POSITIVE\nSEVERITY: CRITICAL | HIGH | MEDIUM | LOW | INFO\nANALYSIS: <explanation>\n\n"
    # Combine header and parts
    return header + "\n".join(parts)


def _parse_batch_response(response: str, batch: List[Finding]) -> None:
    """
    Parses the unstructured text returned by the LLM.
    Updates the finding objects with AI analysis and verification status.
    """
    # Import regex for parsing
    import re

    # Split the raw response into blocks based on the FINDING header
    blocks = re.split(r'FINDING\s+\d+\s*:', response, flags=re.IGNORECASE)
    # Filter out empty blocks and whitespace
    blocks = [b.strip() for b in blocks if b.strip()]

    # Iterate through each finding in the original batch
    for i, finding in enumerate(batch):
        # Handle cases where AI didn't return enough blocks
        if i >= len(blocks):
            # Record failure
            finding.ai_analysis = "AI analysis unavailable for this finding."
            # Continue to next finding
            continue

        # Get the specific block for this finding
        block = blocks[i]

        # Extract the verdict line
        verdict_m = re.search(r'VERDICT\s*:\s*(TRUE_POSITIVE|FALSE_POSITIVE)', block, re.IGNORECASE)
        # Extract the severity line
        severity_m = re.search(r'SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)', block, re.IGNORECASE)
        # Extract the analysis text
        analysis_m = re.search(r'ANALYSIS\s*:\s*(.+?)(?:\n|$)', block, re.IGNORECASE | re.DOTALL)

        # Handle verdict results
        if verdict_m:
            # Check if AI confirmed the vulnerability
            finding.ai_confirmed = verdict_m.group(1).upper() == "TRUE_POSITIVE"
            # If AI thinks it's a false positive
            if not finding.ai_confirmed:
                # Mark as false positive in engine
                finding.false_positive = True

        # Store the AI explanation
        finding.ai_analysis = analysis_m.group(1).strip() if analysis_m else block[:200]


class AIAnalyzer:
    """
    Orchestrator for LLM-powered vulnerability verification.
    Connects to an OpenAI-compatible API to perform deep code analysis.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ):
        """Initialize the AI client and configuration."""
        try:
            # Dynamic import of the OpenAI library
            from openai import OpenAI
        except ImportError:
            # Error if dependency is missing
            raise RuntimeError("openai package is required for AI analysis. Install with: pip install openai")

        # Create the client instance
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        # Set target model
        self.model = model
        # Set randomness level
        self.temperature = temperature
        # Set token limit
        self.max_tokens = max_tokens

    def check_connection(self) -> None:
        """Ping the API to verify connection and API key validity."""
        try:
            # Attempt a minimal API call
            self.client.models.list()
        except Exception as e:
            # Raise descriptive error if connection fails
            raise RuntimeError(f"Could not connect to the AI API or invalid API key. Detailed error: {str(e)}")

    def _chat(self, user_prompt: str) -> str:
        """Low-level wrapper to send a prompt to the AI and return the text response."""
        # Execute chat completion
        response = self.client.chat.completions.create(
            # Pass model
            model=self.model,
            # Pass messages
            messages=[
                # Set system instructions
                {"role": "system", "content": SYSTEM_PROMPT},
                # Set user request
                {"role": "user", "content": user_prompt},
            ],
            # Set parameters
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        # Extract and return content
        return response.choices[0].message.content or ""

    def analyze_findings(self, result: ScanResult, file_contents: dict[str, str] | None = None) -> ScanResult:
        """
        Processes all findings in a scan result through the AI verification pipeline.
        Uses parallel progress display in the terminal.
        """
        # Filter for findings that are currently active
        active = [f for f in result.findings if not f.false_positive]
        # Skip if nothing to analyze
        if not active:
            # Return original result
            return result

        # Split active findings into manageable batches
        batches = _batch_findings(active, batch_size=5)
        # Total number of batches
        total = len(batches)

        # Initialize the rich progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]AI analysis...[/] {task.description}"),
            console=console,
        ) as progress:
            # Add task to progress bar
            task = progress.add_task("", total=total)
            # Iterate through batches
            for i, batch in enumerate(batches):
                # Update status text
                progress.update(task, description=f"Batch {i+1}/{total} ({len(batch)} findings)")
                try:
                    # Construct batch prompt
                    prompt = _build_batch_prompt(batch)
                    # Send to AI
                    response = self._chat(prompt)
                    # Parse results back into objects
                    _parse_batch_response(response, batch)
                except Exception as exc:
                    # Handle batch-level errors
                    for f in batch:
                        # Log error per finding
                        f.ai_analysis = f"AI error: {exc}"
                # Move progress bar forward
                progress.advance(task)

        # Flag the result as having been AI-verified
        result.ai_enabled = True
        # Return updated results
        return result
