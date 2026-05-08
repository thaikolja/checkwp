"""CLI entry point for checkwp — WordPress Plugin Security Checker."""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from checkwp import __version__
from checkwp.scanner.engine import Scanner, ScanResult
from checkwp.scanner.patterns import Severity
from checkwp.report.generator import generate_html_report, generate_json_report

console = Console(stderr=True)

BANNER = r"""[bold gradient(#6366f1,#a855f7)]
     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗████████╗██╗    ██╗██████╗
    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝╚══██╔══╝██║    ██║██╔══██╗
    ██║     ███████║█████╗  ██║     █████╔╝    ██║   ██║ █╗ ██║██████╔╝
    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗    ██║   ██║███╗██║██╔═══╝
    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗   ██║   ╚███╔███╔╝██║
     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝[/]
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkwp",
        description="WordPress Plugin Security Checker — detect malware, backdoors, and vulnerabilities in WordPress plugins.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  checkwp ./my-plugin
  checkwp ./my-plugin -o report.html --deep
  checkwp ./my-plugin --severity high --threads 8
  checkwp ./my-plugin --ai --ai-key sk-... --ai-model gpt-4o
  checkwp ./my-plugin --format json -o results.json
  checkwp ./my-plugin --exclude "tests/*" --exclude "assets/*"
  checkwp ./my-plugin --quick --no-open
        """,
    )

    # ── Positional ──
    parser.add_argument(
        "path",
        help="Path to the WordPress plugin directory to scan.",
    )

    # ── Output Options ──
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path. Default: <plugin-name>-security-report.html",
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["html", "json"],
        default="html",
        help="Report format (default: html).",
    )
    output_group.add_argument(
        "--no-open",
        action="store_true",
        help="Don't auto-open the HTML report in a browser.",
    )
    output_group.add_argument(
        "--stdout",
        action="store_true",
        help="Print the report to stdout instead of writing to a file.",
    )

    # ── Scan Options ──
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "-s", "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity level to report (default: info).",
    )
    scan_group.add_argument(
        "--deep",
        action="store_true",
        help="Enable deep scanning (entropy analysis, broader pattern matching). Slower but more thorough.",
    )
    scan_group.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan — critical and high severity only, reduced context.",
    )
    scan_group.add_argument(
        "-t", "--threads",
        type=int,
        default=4,
        help="Number of parallel scanning threads (default: 4).",
    )
    scan_group.add_argument(
        "--max-file-size",
        type=int,
        default=2048,
        help="Maximum file size to scan in KB (default: 2048).",
    )
    scan_group.add_argument(
        "--context-lines",
        type=int,
        default=3,
        help="Number of context lines around each finding (default: 3).",
    )

    # ── Filter Options ──
    filter_group = parser.add_argument_group("Filter Options")
    filter_group.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Directory names to exclude from scanning (repeatable).",
    )
    filter_group.add_argument(
        "--include-ext",
        action="append",
        default=[],
        help="Additional file extensions to include, e.g. '.twig' (repeatable).",
    )
    filter_group.add_argument(
        "--php-only",
        action="store_true",
        help="Scan PHP files only.",
    )
    filter_group.add_argument(
        "--js-only",
        action="store_true",
        help="Scan JavaScript/TypeScript files only.",
    )

    # ── AI Options ──
    ai_group = parser.add_argument_group("AI-Enhanced Analysis (Optional)")
    ai_group.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI-enhanced vulnerability analysis.",
    )
    ai_group.add_argument(
        "--ai-key",
        default=None,
        help="API key for the AI provider. Can also use CHECKWP_AI_KEY env var.",
    )
    ai_group.add_argument(
        "--ai-provider",
        default="https://api.openai.com/v1",
        help="Base URL for OpenAI-compatible API (default: https://api.openai.com/v1).",
    )
    ai_group.add_argument(
        "--ai-model",
        default="gpt-4o",
        help="Model name to use for AI analysis (default: gpt-4o).",
    )
    ai_group.add_argument(
        "--ai-temperature",
        type=float,
        default=0.1,
        help="Temperature for AI model (default: 0.1 for deterministic analysis).",
    )

    # ── Display Options ──
    display_group = parser.add_argument_group("Display Options")
    display_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv).",
    )
    display_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all console output except errors.",
    )
    display_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't show the ASCII banner.",
    )
    display_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored console output.",
    )

    # ── Meta ──
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"checkwp v{__version__}",
    )

    return parser


def _severity_from_str(s: str) -> Severity:
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW, "info": Severity.INFO}[s.lower()]


def _print_summary(result: ScanResult) -> None:
    """Print a rich summary table to stderr."""
    grade = result.grade()
    color = result.grade_color()

    console.print()
    console.print(Panel(
        f"[bold]Grade: [{color}]{grade}[/{color}][/bold]  •  "
        f"[red]{result.critical_count} Critical[/]  •  "
        f"[dark_orange]{result.high_count} High[/]  •  "
        f"[yellow]{result.medium_count} Medium[/]  •  "
        f"[blue]{result.low_count} Low[/]  •  "
        f"[dim]{result.info_count} Info[/]",
        title=f"[bold white]{result.plugin_name}[/]",
        subtitle=f"{len(result.files_scanned)} files • {result.scan_duration}s",
        border_style="bright_blue",
    ))

    if result.total_findings > 0:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=18)
        table.add_column("Title", min_width=30)
        table.add_column("File", style="cyan")
        table.add_column("Line", justify="right", width=5)

        active = [f for f in result.findings if not f.false_positive]
        for i, f in enumerate(active[:20], 1):
            sev_colors = {5: "red", 4: "dark_orange", 3: "yellow", 2: "blue", 1: "dim"}
            sc = sev_colors.get(f.severity.value, "white")
            table.add_row(str(i), f"[{sc}]{f.severity.label}[/]", f.pattern.id, f.pattern.title, f.file_path, str(f.line_number))

        console.print(table)

        if len(active) > 20:
            console.print(f"\n  [dim]... and {len(active) - 20} more findings. See full report.[/dim]")

    console.print()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        console._force_terminal = False

    # Show banner
    if not args.quiet and not args.no_banner:
        console.print(BANNER)

    # Validate path
    target = os.path.abspath(args.path)
    if not os.path.exists(target):
        console.print(f"[red bold]Error:[/] '{args.path}' does not exist.")
        return 1
    
    if not os.path.isdir(target) and not target.lower().endswith(".zip"):
        console.print(f"[red bold]Error:[/] '{args.path}' must be a directory or a .zip file.")
        return 1

    # Build include extensions
    include_ext = None
    if args.php_only:
        include_ext = {".php", ".inc", ".module"}
    elif args.js_only:
        include_ext = {".js", ".jsx", ".ts", ".tsx", ".mjs"}
    elif args.include_ext:
        from checkwp.scanner.engine import DEFAULT_EXTENSIONS
        include_ext = DEFAULT_EXTENSIONS | set(args.include_ext)

    # Build exclude dirs
    from checkwp.scanner.engine import DEFAULT_EXCLUDE
    exclude_dirs = DEFAULT_EXCLUDE | set(args.exclude)

    # Severity
    severity = _severity_from_str(args.severity)
    if args.quick:
        severity = Severity.HIGH

    # Scanner
    if not args.quiet:
        console.print(f"[bold cyan]Scanning:[/] {target}")
        console.print(f"[dim]Mode: {'deep' if args.deep else ('quick' if args.quick else 'standard')} • Threads: {args.threads} • Min severity: {severity.label}[/dim]")
        console.print()

    scanner = Scanner(
        target,
        severity_threshold=severity,
        max_file_size_kb=args.max_file_size,
        exclude_dirs=exclude_dirs,
        include_extensions=include_ext,
        deep_scan=args.deep,
        threads=args.threads,
        context_lines=args.context_lines,
    )

    from rich.progress import Progress, SpinnerColumn, TextColumn
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Scanning files...[/]"), console=console, disable=args.quiet) as progress:
        task = progress.add_task("scan", total=None)
        result = scanner.scan()

    # AI analysis
    if args.ai:
        api_key = args.ai_key or os.environ.get("CHECKWP_AI_KEY")
        if not api_key:
            console.print("[red bold]Error:[/] AI mode requires --ai-key or CHECKWP_AI_KEY environment variable.")
            return 1

        if not args.quiet:
            console.print(f"\n[bold indigo]AI Analysis:[/] {args.ai_model} via {args.ai_provider}")

        try:
            from checkwp.ai.analyzer import AIAnalyzer
            analyzer = AIAnalyzer(
                api_key=api_key,
                model=args.ai_model,
                base_url=args.ai_provider,
                temperature=args.ai_temperature,
            )
            result = analyzer.analyze_findings(result)
        except Exception as exc:
            console.print(f"[red]AI analysis failed:[/] {exc}")
            result.errors.append(f"AI analysis failed: {exc}")

    # Summary
    if not args.quiet:
        _print_summary(result)

    # Generate report
    if args.format == "json":
        report_content = generate_json_report(result)
        default_ext = ".json"
    else:
        report_content = generate_html_report(result)
        default_ext = ".html"

    if args.stdout:
        sys.stdout.write(report_content)
        return 0

    output_path = args.output or f"{result.plugin_name}-security-report{default_ext}"
    output_path = os.path.abspath(output_path)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    if not args.quiet:
        console.print(f"[green bold]✓[/] Report saved to [cyan]{output_path}[/]")

    # Auto-open HTML
    if args.format == "html" and not args.no_open and not args.quiet:
        try:
            if sys.platform == 'darwin':
                import subprocess
                subprocess.call(('open', output_path))
            elif sys.platform in ['win32', 'cygwin']:
                os.startfile(output_path)
            else:
                webbrowser.open(f"file://{output_path}")
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
