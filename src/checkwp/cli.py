"""
CLI entry point for checkwp — WordPress Plugin Security Checker.
This script handles user input, configures the scanner, and triggers report generation.
"""

# Enable future type annotations
from __future__ import annotations

import argparse
import os
import sys
import webbrowser

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from checkwp import __version__
from checkwp.report.generator import generate_html_report, generate_json_report
from checkwp.scanner.engine import Scanner, ScanResult
from checkwp.scanner.patterns import Severity

# Initialize a global console object for stderr output
console = Console(stderr=True)

# Define the stylized ASCII banner for the CLI
BANNER = r"""[bold gradient(#6366f1,#a855f7)]
     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗████████╗██╗    ██╗██████╗
    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝╚══██╔══╝██║    ██║██╔══██╗
    ██║     ███████║█████╗  ██║     █████╔╝    ██║   ██║ █╗ ██║██████╔╝
    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗    ██║   ██║███╗██║██╔═══╝
    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗   ██║   ╚███╔███╔╝██║
     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝[/]
"""


def _build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser with all groups and options."""
    # Initialize the main parser object
    parser = argparse.ArgumentParser(
        # Set program name
        prog="checkwp",
        # Set project description
        description=(
            "WordPress Plugin Security Checker — detect malware, backdoors, "
            "and vulnerabilities in WordPress plugins."
        ),
        # Use raw formatter to preserve formatting in epilog
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Add usage examples and author info to the bottom of the help
        epilog="""
Examples:
  checkwp ./my-plugin
  checkwp ./my-plugin -o report.html --deep
  checkwp ./my-plugin --severity high --threads 8
  checkwp ./my-plugin --ai --ai-key sk-... --ai-model gpt-4o
  checkwp ./my-plugin --format json -o results.json
  checkwp ./my-plugin --exclude "tests/*" --exclude "assets/*"
  checkwp ./my-plugin --quick --no-open

Author:
  Kolja Nolte <kolja.nolte@gmail.com>
        """,
    )

    # ── Positional Arguments ──
    # Define the main target path argument
    parser.add_argument(
        # Parameter name
        "path",
        # Help description
        help="Path to the WordPress plugin directory to scan.",
    )

    # ── Output Configuration Group ──
    # Create a group for output-related flags
    output_group = parser.add_argument_group("Output Options")
    # Add option for custom output file path
    output_group.add_argument(
        # Short and long flags
        "-o", "--output",
        # Default is None
        default=None,
        # Help description
        help="Output file path. Default: <plugin-name>-security-report.html",
    )
    # Add option for report format
    output_group.add_argument(
        # Short and long flags
        "-f", "--format",
        # Restrict to specific choices
        choices=["html", "json"],
        # Default to HTML
        default="html",
        # Help description
        help="Report format (default: html).",
    )
    # Add flag to disable auto-opening the browser
    output_group.add_argument(
        # Long flag
        "--no-open",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Don't auto-open the HTML report in a browser.",
    )
    # Add flag to output directly to terminal
    output_group.add_argument(
        # Long flag
        "--stdout",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Print the report to stdout instead of writing to a file.",
    )

    # ── Scan Engine Configuration Group ──
    # Create a group for scanner behavior flags
    scan_group = parser.add_argument_group("Scan Options")
    # Add option for minimum severity filtering
    scan_group.add_argument(
        # Short and long flags
        "-s", "--severity",
        # Allowed severity labels
        choices=["critical", "high", "medium", "low"],
        # Default to showing everything (low and up)
        default="low",
        # Help description
        help="Minimum severity level to report (default: low).",
    )
    # Add flag for entropy/deep analysis
    scan_group.add_argument(
        # Long flag
        "--deep",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Enable deep scanning (entropy analysis, broader pattern matching). Slower but more thorough.",
    )
    # Add flag for a faster, high-level scan
    scan_group.add_argument(
        # Long flag
        "--quick",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Quick scan — critical and high severity only, reduced context.",
    )
    # Add option for thread count
    scan_group.add_argument(
        # Short and long flags
        "-t", "--threads",
        # Expect integer input
        type=int,
        # Default to 4 threads
        default=4,
        # Help description
        help="Number of parallel scanning threads (default: 4).",
    )
    # Add option for file size limit
    scan_group.add_argument(
        # Long flag
        "--max-file-size",
        # Expect integer input
        type=int,
        # Default to 2MB
        default=2048,
        # Help description
        help="Maximum file size to scan in KB (default: 2048).",
    )
    # Add option for code context window
    scan_group.add_argument(
        # Long flag
        "--context-lines",
        # Expect integer input
        type=int,
        # Default to 3 lines
        default=3,
        # Help description
        help="Number of context lines around each finding (default: 3).",
    )

    # ── Directory and File Filter Group ──
    # Create a group for exclusion and inclusion logic
    filter_group = parser.add_argument_group("Filter Options")
    # Add option to exclude specific directories
    filter_group.add_argument(
        # Long flag
        "--exclude",
        # Allow multiple occurrences
        action="append",
        # Default to empty list
        default=[],
        # Help description
        help="Directory names to exclude from scanning (repeatable).",
    )
    # Add option to include extra file extensions
    filter_group.add_argument(
        # Long flag
        "--include-ext",
        # Allow multiple occurrences
        action="append",
        # Default to empty list
        default=[],
        # Help description
        help="Additional file extensions to include, e.g. '.twig' (repeatable).",
    )
    # Add flag to restrict scan to PHP files
    filter_group.add_argument(
        # Long flag
        "--php-only",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Scan PHP files only.",
    )
    # Add flag to restrict scan to JS files
    filter_group.add_argument(
        # Long flag
        "--js-only",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Scan JavaScript/TypeScript files only.",
    )

    # ── AI Integration Group ──
    # Create a group for optional AI analysis settings
    ai_group = parser.add_argument_group("AI-Enhanced Analysis (Optional)")
    # Add flag to enable AI features
    ai_group.add_argument(
        # Long flag
        "--ai",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Enable AI-enhanced vulnerability analysis.",
    )
    # Add option for AI API key
    ai_group.add_argument(
        # Long flag
        "--ai-key",
        # Default to None
        default=None,
        # Help description
        help="API key for the AI provider. Can also use CHECKWP_AI_KEY env var.",
    )
    # Add option for AI API base URL
    ai_group.add_argument(
        # Long flag
        "--ai-provider",
        # Default to OpenAI
        default="https://api.openai.com/v1",
        # Help description
        help="Base URL for OpenAI-compatible API (default: https://api.openai.com/v1).",
    )
    # Add option for the AI model identifier
    ai_group.add_argument(
        # Long flag
        "--ai-model",
        # Default to gpt-4o
        default="gpt-4o",
        # Help description
        help="Model name to use for AI analysis (default: gpt-4o).",
    )
    # Add option for AI creativity parameter
    ai_group.add_argument(
        # Long flag
        "--ai-temperature",
        # Expect float input
        type=float,
        # Default to very low (accurate)
        default=0.1,
        # Help description
        help="Temperature for AI model (default: 0.1 for deterministic analysis).",
    )

    # ── Display and UI Group ──
    # Create a group for terminal output styling
    display_group = parser.add_argument_group("Display Options")
    # Add option for verbosity level
    display_group.add_argument(
        # Short and long flags
        "-v", "--verbose",
        # Increment counter per occurrence
        action="count",
        # Start at 0
        default=0,
        # Help description
        help="Increase verbosity (-v, -vv, -vvv).",
    )
    # Add flag for minimal output
    display_group.add_argument(
        # Short and long flags
        "-q", "--quiet",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Suppress all console output except errors.",
    )
    # Add flag to hide the banner
    display_group.add_argument(
        # Long flag
        "--no-banner",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Don't show the ASCII banner.",
    )
    # Add flag to disable colors
    display_group.add_argument(
        # Long flag
        "--no-color",
        # Store as boolean true
        action="store_true",
        # Help description
        help="Disable colored console output.",
    )

    # ── Metadata ──
    # Add standard version flag
    parser.add_argument(
        # Short and long flags
        "-V", "--version",
        # Built-in version action
        action="version",
        # Format string for version output
        version=f"checkwp v{__version__}",
    )

    # Return the completed parser object
    return parser


def _severity_from_str(s: str) -> Severity:
    """Map a case-insensitive string label to a Severity enum value."""
    # Return mapped enum based on lowercase input string
    return {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
            "low": Severity.LOW}[s.lower()]


def _print_nonfatal_errors(result: ScanResult) -> None:
    """Print scanner warnings that did not stop the scan from completing."""
    # Skip rendering when there are no warnings to show
    if not result.errors:
        # Nothing to print
        return

    # Render a compact warning panel with one line per captured issue
    console.print(
        Panel(
            "\n".join(f"• {error}" for error in result.errors),
            title="[bold yellow]Warnings[/]",
            border_style="yellow",
        )
    )


def _print_summary(result: ScanResult) -> None:
    """Print a rich summary table to stderr including grade and counts."""
    # Get the security grade string
    grade = result.grade()
    # Get the HEX color for the grade
    color = result.grade_color()

    # Print a newline for spacing
    console.print()
    # Render the main summary panel
    console.print(Panel(
        # Display the grade with dynamic coloring
        f"[bold]Grade: [{color}]{grade}[/{color}][/bold]  •  "
        # Display critical finding count
        f"[red]{result.critical_count} Critical[/]  •  "
        # Display high finding count
        f"[dark_orange]{result.high_count} High[/]  •  "
        # Display medium finding count
        f"[yellow]{result.medium_count} Medium[/]  •  "
        # Display low finding count
        f"[blue]{result.low_count} Low[/]",
        # Use plugin name as panel title
        title=f"[bold white]{result.plugin_name}[/]",
        # Show file count and duration as subtitle
        subtitle=f"{len(result.files_scanned)} files • {result.scan_duration}s",
        # Set border color
        border_style="bright_blue",
    ))

    # If findings exist, print the detailed findings table
    if result.total_findings > 0:
        # Initialize rich table
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        # Add index column
        table.add_column("#", style="dim", width=4)
        # Add severity column
        table.add_column("Severity", width=10)
        # Add rule ID column
        table.add_column("Rule", width=18)
        # Add title column
        table.add_column("Title", min_width=30)
        # Add file path column
        table.add_column("File", style="cyan")
        # Add line number column
        table.add_column("Line", justify="right", width=5)

        # Filter for true findings (non-FPs)
        active = [f for f in result.findings if not f.false_positive]
        # Iterate through top 20 findings
        for i, f in enumerate(active[:20], 1):
            # Define color map for terminal
            sev_colors = {5: "red", 4: "dark_orange", 3: "yellow", 2: "blue"}
            # Get color or default to white
            sc = sev_colors.get(f.severity.value, "white")
            # Add data row to the table
            table.add_row(
                str(i),
                f"[{sc}]{f.severity.label}[/]",
                f.pattern.id,
                f.pattern.title,
                f.file_path,
                str(f.line_number),
            )

        # Print the completed table
        console.print(table)

        # Show indicator if there are more findings not listed
        if len(active) > 20:
            # Print truncated message
            console.print(f"\n  [dim]... and {len(active) - 20} more findings. See full report.[/dim]")

    # Print trailing newline
    console.print()


def main(argv: list[str] | None = None) -> int:
    """
    Main CLI entry point logic.
    Coordinates parsing, scanner setup, AI analysis, and report generation.
    """
    # Import sys for argument checking
    import sys
    # Check if we were called with no arguments
    if (argv is None and len(sys.argv) <= 1) or (argv is not None and not argv):
        # Print help automatically if no input provided
        _build_parser().print_help()
        # Exit with error code
        return 1

    # Instantiate the argument parser
    parser = _build_parser()
    # Parse the command line arguments
    args = parser.parse_args(argv)

    # Reject incompatible file-type filters explicitly
    if args.php_only and args.js_only:
        # Print error message
        console.print("[red bold]Error:[/] --php-only and --js-only cannot be used together.")
        # Exit with failure
        return 1

    # Validate numeric options so the scanner receives sane values
    if args.threads < 1:
        # Print error message
        console.print("[red bold]Error:[/] --threads must be at least 1.")
        # Exit with failure
        return 1
    # Validate file size limit to avoid silently skipping everything
    if args.max_file_size <= 0:
        # Print error message
        console.print("[red bold]Error:[/] --max-file-size must be greater than 0.")
        # Exit with failure
        return 1
    # Validate context line count so list slicing remains intentional
    if args.context_lines < 0:
        # Print error message
        console.print("[red bold]Error:[/] --context-lines cannot be negative.")
        # Exit with failure
        return 1

    # Handle color disabling flag
    if args.no_color:
        # Tell rich to stop using terminal colors
        console._force_terminal = False

    # Conditionally show the startup banner
    if not args.quiet and not args.no_banner:
        # Print the ASCII BANNER
        console.print(BANNER)

    # Convert provided target path to absolute path
    target = os.path.abspath(args.path)
    # Check if the target path exists on disk
    if not os.path.exists(target):
        # Print error message
        console.print(f"[red bold]Error:[/] '{args.path}' does not exist.")
        # Return failure code
        return 1

    # Ensure target is either a directory or a zip archive
    if not os.path.isdir(target) and not target.lower().endswith(".zip"):
        # Print error message
        console.print(f"[red bold]Error:[/] '{args.path}' must be a directory or a .zip file.")
        # Return failure code
        return 1

    # Logic to build the set of extensions to include in the scan
    include_ext = None
    # Handle PHP only mode
    if args.php_only:
        # Set extension set
        include_ext = {".php", ".inc", ".module"}
    # Handle JS only mode
    elif args.js_only:
        # Set extension set
        include_ext = {".js", ".jsx", ".ts", ".tsx", ".mjs"}
    # Handle user-defined additional extensions
    elif args.include_ext:
        # Import defaults
        from checkwp.scanner.engine import DEFAULT_EXTENSIONS
        # Merge defaults with user provided extensions
        include_ext = DEFAULT_EXTENSIONS | set(args.include_ext)

    # Logic to build the set of directories to exclude
    from checkwp.scanner.engine import DEFAULT_EXCLUDE
    # Merge default excludes with user provided exclusions
    exclude_dirs = DEFAULT_EXCLUDE | set(args.exclude)

    # Convert the severity string argument into the internal Enum type
    severity = _severity_from_str(args.severity)
    # Override severity if quick mode is enabled
    if args.quick:
        # Force high severity threshold
        severity = Severity.HIGH

    # Print start message if not in quiet mode
    if not args.quiet:
        # Show target path
        console.print(f"[bold cyan]Scanning:[/] {target}")
        # Show configuration summary line
        scan_mode = "deep" if args.deep else ("quick" if args.quick else "standard")
        console.print(
            f"[dim]Mode: {scan_mode} • Threads: {args.threads} • Min severity: {severity.label}[/dim]"
        )
        # Extra spacing
        console.print()

    # Initialize the core Scanner engine with all configuration parameters
    scanner = Scanner(
        # Set target path
        target,
        # Set severity filter
        severity_threshold=severity,
        # Set file size limit
        max_file_size_kb=args.max_file_size,
        # Set directory exclusions
        exclude_dirs=exclude_dirs,
        # Set extension inclusions
        include_extensions=include_ext,
        # Set deep scan toggle
        deep_scan=args.deep,
        # Set thread count
        threads=args.threads,
        # Set context capture size
        context_lines=args.context_lines,
    )

    # Import rich components for the progress bar
    from rich.progress import Progress, SpinnerColumn, TextColumn
    # Run the scan inside a rich progress context
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Scanning files...[/]"),
        console=console,
        disable=args.quiet,
    ):
        # Add a placeholder task for the progress bar
        # Execute the scan operation
        result = scanner.scan()

    # Treat hard scan failures as fatal CLI errors with clear messages
    fatal_errors = [
        error
        for error in result.errors
        if error.startswith(
            (
                "Invalid WordPress plugin:",
                "Invalid ZIP archive:",
                "Failed to extract ZIP:",
                "No scannable files found",
                "Target must be a directory or a valid .zip file.",
            )
        )
    ]
    if fatal_errors:
        # Print the first fatal error
        console.print(f"\n[red bold]✖ Scan Failed:[/] {fatal_errors[0]}")
        # Exit with failure
        return 1

    # Logic for optional AI analysis if requested by the user
    if args.ai:
        # Fetch API key from arguments or environment variable
        api_key = args.ai_key or os.environ.get("CHECKWP_AI_KEY")
        # Ensure a key is available
        if not api_key:
            # Print error and exit
            console.print("[red bold]Error:[/] AI mode requires --ai-key or CHECKWP_AI_KEY environment variable.")
            # Return failure
            return 1

        # Show AI initialization message
        if not args.quiet:
            # Display model and provider info
            console.print(f"\n[bold indigo]AI Analysis:[/] {args.ai_model} via {args.ai_provider}")

        try:
            # Late import of the AI analyzer to save startup time if not used
            from checkwp.ai.analyzer import AIAnalyzer
            # Initialize AI analyzer
            analyzer = AIAnalyzer(
                # Set API key
                api_key=api_key,
                # Set model name
                model=args.ai_model,
                # Set base URL
                base_url=args.ai_provider,
                # Set temperature
                temperature=args.ai_temperature,
            )

            # Verify connectivity before starting batch analysis
            analyzer.check_connection()

            # Run the AI verification on findings
            result = analyzer.analyze_findings(result)
            # Store metadata in result
            result.ai_model = args.ai_model
            # Estimate token usage
            result.ai_tokens = len(result.findings) * 850 + 1200 # Appx tokens

        except Exception as exc:
            # Handle AI-specific errors gracefully
            console.print(f"\n[bold red]✖ AI Analysis Connection Failed:[/] {exc}")
            # Inform user that scan proceeds without AI
            console.print("[yellow]The scan will proceed, but AI deep verification has been disabled.[/]")
            # Log error in result object
            result.errors.append(f"AI analysis failed: {exc}")

    # Display the final summary dashboard if not in quiet mode
    if not args.quiet:
        # Print non-fatal warnings first so the summary still reflects the completed scan
        _print_nonfatal_errors(result)
        # Print summary panel and table
        _print_summary(result)

    # Report generation logic based on user's requested format
    if args.format == "json":
        # Generate JSON string
        report_content = generate_json_report(result)
        # Set file extension
        default_ext = ".json"
    else:
        # Generate HTML string
        report_content = generate_html_report(result)
        # Set file extension
        default_ext = ".html"

    # Handle direct stdout output mode
    if args.stdout:
        # Write content to system stdout
        sys.stdout.write(report_content)
        # Exit successfully
        return 0

    # Determine final output file path
    output_path = args.output or f"{result.plugin_name}-security-report{default_ext}"
    # Convert to absolute path
    output_path = os.path.abspath(output_path)

    # Write report content to disk
    try:
        # Open the report file for writing
        with open(output_path, "w", encoding="utf-8") as f:
            # Write string to file
            f.write(report_content)
    except OSError as exc:
        # Print a clear write error instead of a stack trace
        console.print(f"[red bold]Error:[/] Could not write report: {exc}")
        # Exit with failure
        return 1

    # Inform user of saved report
    if not args.quiet:
        # Print confirmation message
        console.print(f"[green bold]✓[/] Report saved to [cyan]{output_path}[/]")

    # Logic to automatically launch the HTML report in a browser
    if args.format == "html" and not args.no_open and not args.quiet:
        try:
            # Handle macOS specific open command
            if sys.platform == 'darwin':
                # Import subprocess for system calls
                import subprocess
                # Run the open command
                subprocess.call(('open', output_path))
            # Handle Windows specific file association launch
            elif sys.platform in ['win32', 'cygwin']:
                # Run startfile
                os.startfile(output_path)
            # Handle Linux and other platforms
            else:
                # Use standard webbrowser module
                webbrowser.open(f"file://{output_path}")
        except Exception:
            # Ignore browser launch errors
            pass

    # Return success exit code
    return 0


# Execute main function if script is run directly
if __name__ == "__main__":
    # Exit with return code from main
    sys.exit(main())
