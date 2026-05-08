"""
Core scanning engine — orchestrates file discovery, pattern matching, and analysis.
This module handles the heavy lifting of finding files, checking headers, and identifying vulnerabilities.
"""

# Import type annotations for compatibility
import hashlib
import math
import os
import re
import shutil
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

# Import chardet for character encoding detection
import chardet

# Import constants and severity enums from patterns module
from wpcheck.scanner.patterns import (
    ALL_PATTERNS,
    LANGUAGE_EXTENSIONS,
    Severity,
    VulnPattern,
)


@dataclass
class Finding:
    """
    Represents a single vulnerability finding identified during a scan.
    Contains metadata about the rule, file location, and AI analysis results.
    """
    # The vulnerability pattern that was matched
    pattern: VulnPattern
    # The path to the file containing the finding
    file_path: str
    # The line number where the match occurred
    line_number: int
    # The column offset where the match started
    match_column: int
    # The content of the line where the match occurred
    line_content: str
    # Lines of code appearing before the finding for context
    context_before: list[str] = field(default_factory=list)
    # Lines of code appearing after the finding for context
    context_after: list[str] = field(default_factory=list)
    # The analysis text provided by an AI model
    ai_analysis: str | None = None
    # Whether an AI model confirmed the finding as a true positive
    ai_confirmed: bool | None = None
    # Flag indicating if the finding is considered a false positive
    false_positive: bool = False

    @property
    def severity(self) -> Severity:
        """Helper property to get the severity from the pattern."""
        # Return the severity level of the associated pattern
        return self.pattern.severity

    @property
    def relative_path(self) -> str:
        """Helper property to get the file path."""
        # Return the file path string
        return self.file_path


@dataclass
class FileInfo:
    """
    Metadata about a specific file scanned by the engine.
    Used for reporting file inventory and entropy checks.
    """
    # Absolute path to the file on disk
    path: str
    # Path relative to the plugin root
    relative_path: str
    # Size of the file in bytes
    size: int
    # File extension including the dot
    extension: str
    # SHA256 checksum of the file content
    sha256: str
    # Detected programming language
    language: str
    # Total number of lines in the file
    lines: int
    # Calculated Shannon entropy (0.0 to 8.0)
    entropy: float = 0.0


@dataclass
class ScanResult:
    """
    The final object returned by a scan operation.
    Aggregates all findings, file metadata, and scan execution statistics.
    """
    # The original path provided for the scan
    plugin_path: str
    # The detected or extracted name of the plugin
    plugin_name: str
    # List of all identified findings
    findings: list[Finding] = field(default_factory=list)
    # List of metadata for all successfully scanned files
    files_scanned: list[FileInfo] = field(default_factory=list)
    # List of file paths that were skipped during the scan
    files_skipped: list[str] = field(default_factory=list)
    # Time taken to complete the scan in seconds
    scan_duration: float = 0.0
    # Whether AI analysis was performed
    ai_enabled: bool = False
    # The name of the AI model used for analysis
    ai_model: str = ""
    # Estimated number of tokens used for AI analysis
    ai_tokens: int = 0
    # The mode used for scanning (e.g., 'standard' or 'deep')
    scan_mode: str = "standard"
    # List of error messages encountered during the scan
    errors: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Count findings that are not marked as false positives."""
        # Filter findings and return the count of true positives
        return len([f for f in self.findings if not f.false_positive])

    @property
    def critical_count(self) -> int:
        """Count critical severity findings."""
        # Filter and count non-FP findings with critical severity
        return len([f for f in self.findings if f.severity == Severity.CRITICAL and not f.false_positive])

    @property
    def high_count(self) -> int:
        """Count high severity findings."""
        # Filter and count non-FP findings with high severity
        return len([f for f in self.findings if f.severity == Severity.HIGH and not f.false_positive])

    @property
    def medium_count(self) -> int:
        """Count medium severity findings."""
        # Filter and count non-FP findings with medium severity
        return len([f for f in self.findings if f.severity == Severity.MEDIUM and not f.false_positive])

    @property
    def low_count(self) -> int:
        """Count low severity findings."""
        # Filter and count non-FP findings with low severity
        return len([f for f in self.findings if f.severity == Severity.LOW and not f.false_positive])

    @property
    def info_count(self) -> int:
        """Historical count for info findings (deprecated)."""
        # Return 0 as info severity was removed
        return 0

    def grade(self) -> str:
        """
        Calculate an overall security grade (A+ through F) based on finding severity.
        The algorithm subtracts points for each true positive finding.
        """
        # Start with a perfect score of 100
        score = 100
        # Iterate through every finding in the list
        for f in self.findings:
            # Skip findings marked as false positives
            if f.false_positive:
                # Continue to next finding
                continue
            # Deduct 25 points for each critical finding
            if f.severity == Severity.CRITICAL:
                # Update score
                score -= 25
            # Deduct 12 points for each high finding
            elif f.severity == Severity.HIGH:
                # Update score
                score -= 12
            # Deduct 5 points for each medium finding
            elif f.severity == Severity.MEDIUM:
                # Update score
                score -= 5
            # Deduct 2 points for each low finding
            elif f.severity == Severity.LOW:
                # Update score
                score -= 2
        # Ensure the score does not drop below zero
        score = max(0, score)
        # Return A+ for scores 97 and above
        if score >= 97:
            # Return string
            return "A+"
        # Return A for scores 93 and above
        elif score >= 93:
            # Return string
            return "A"
        # Return A- for scores 90 and above
        elif score >= 90:
            # Return string
            return "A-"
        # Return B+ for scores 87 and above
        elif score >= 87:
            # Return string
            return "B+"
        # Return B for scores 83 and above
        elif score >= 83:
            # Return string
            return "B"
        # Return B- for scores 80 and above
        elif score >= 80:
            # Return string
            return "B-"
        # Return C+ for scores 77 and above
        elif score >= 77:
            # Return string
            return "C+"
        # Return C for scores 73 and above
        elif score >= 73:
            # Return string
            return "C"
        # Return C- for scores 70 and above
        elif score >= 70:
            # Return string
            return "C-"
        # Return D+ for scores 67 and above
        elif score >= 67:
            # Return string
            return "D+"
        # Return D for scores 63 and above
        elif score >= 63:
            # Return string
            return "D"
        # Return D- for scores 60 and above
        elif score >= 60:
            # Return string
            return "D-"
        # Default to F for low scores
        else:
            # Return string
            return "F"

    def grade_color(self) -> str:
        """Return a HEX color string corresponding to the calculated grade."""
        # Get the letter grade
        g = self.grade()
        # Return green for A grades
        if g.startswith("A"):
            # HEX color code
            return "#22c55e"
        # Return blue for B grades
        elif g.startswith("B"):
            # HEX color code
            return "#3b82f6"
        # Return yellow for C grades
        elif g.startswith("C"):
            # HEX color code
            return "#eab308"
        # Return orange for D grades
        elif g.startswith("D"):
            # HEX color code
            return "#f97316"
        # Return red for F or other failures
        return "#ef4444"


# Standard directories to skip during scanning
DEFAULT_EXCLUDE = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
    ".DS_Store", "Thumbs.db",
}

# Set of file extensions to include based on language map
DEFAULT_EXTENSIONS: set[str] = set()
# Loop through language map and add all extensions
for exts in LANGUAGE_EXTENSIONS.values():
    # Update set with extensions
    DEFAULT_EXTENSIONS.update(exts)

# Set of binary extensions to skip entirely
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".rar",
    ".pdf", ".doc", ".docx",
    ".mp3", ".mp4", ".avi", ".mov",
    ".exe", ".dll", ".so", ".dylib",
    ".mo", ".po",
}

# Maximum number of bytes to read from a text file in a single pass
MAX_TEXT_READ_BYTES = 2 * 1024 * 1024

# Only the beginning of plugin files is needed for header validation
PLUGIN_HEADER_READ_BYTES = 64 * 1024

# Guard rail against extremely large ZIP archives during extraction
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def _calculate_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte string.
    Scale is 0 to 8, where higher means more randomness (obfuscation).
    """
    # Return 0 if data is empty
    if not data:
        # Avoid division by zero
        return 0.0
    # Map byte values to their frequency counts
    freq: dict[int, int] = {}
    # Iterate through every byte
    for byte in data:
        # Increment frequency map
        freq[byte] = freq.get(byte, 0) + 1
    # Get total length of data
    length = len(data)
    # Initialize entropy accumulator
    entropy = 0.0
    # Calculate probability for each byte value
    for count in freq.values():
        # Get probability
        p = count / length
        # Add to entropy if probability is non-zero
        if p > 0:
            # Apply Shannon entropy formula
            entropy -= p * math.log2(p)
    # Return rounded entropy value
    return round(entropy, 4)


def _detect_language(ext: str) -> str:
    """Map a file extension to a language name using the patterns database."""
    # Loop through language mapping
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        # Check if extension exists in current language
        if ext in exts:
            # Return language name
            return lang
    # Default to unknown
    return "unknown"


def _read_file_safe(path: str, *, max_bytes: int = MAX_TEXT_READ_BYTES) -> str | None:
    """
    Attempt to read a file with intelligent encoding detection.
    Skips binary files and handles decode errors gracefully.
    """
    try:
        # Read a bounded amount of data from disk to avoid memory spikes
        with Path(path).open("rb") as file_obj:
            # Read at most one byte past the configured limit so we can truncate safely
            raw = file_obj.read(max_bytes + 1)
        # Truncate oversized content to the allowed read window
        raw = raw[:max_bytes]
        # Check for null bytes which indicate binary content
        if b"\x00" in raw[:8192]:
            # Skip binary files
            return None
        # Detect character encoding using chardet
        detected = chardet.detect(raw[:10000])
        # Get detected encoding or default to utf-8
        encoding = detected.get("encoding") or "utf-8"
        try:
            # Attempt decoding with detected encoding
            return raw.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            # Fallback to utf-8 if detection fails
            return raw.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        # Return None if file cannot be read
        return None


class Scanner:
    """
    The main coordinator class for the security scan.
    Handles discovery, validation, parallel processing, and result aggregation.
    """

    def __init__(
        self,
        target_path: str,
        *,
        severity_threshold: Severity = Severity.LOW,
        max_file_size_kb: int = 2048,
        exclude_dirs: set[str] | None = None,
        include_extensions: set[str] | None = None,
        deep_scan: bool = False,
        threads: int = 4,
        context_lines: int = 3,
    ):
        """Initialize the scanner with user-defined options."""
        # Convert to absolute path
        self.target_path = os.path.abspath(target_path)
        # Set minimum severity to report
        self.severity_threshold = severity_threshold
        # Convert KB to bytes
        self.max_file_size = max_file_size_kb * 1024
        # Set excluded directories or use defaults
        self.exclude_dirs = set(exclude_dirs) if exclude_dirs is not None else set(DEFAULT_EXCLUDE)
        # Set included extensions or use defaults
        self.include_extensions = (
            {ext.lower() for ext in include_extensions}
            if include_extensions is not None
            else set(DEFAULT_EXTENSIONS)
        )
        # Toggle entropy analysis
        self.deep_scan = deep_scan
        # Cap threads to at least 1
        self.threads = max(1, threads)
        # Number of surrounding code lines to capture
        self.context_lines = context_lines
        # Load all vulnerability signatures
        self._patterns = ALL_PATTERNS
        # Initialize temp directory tracker
        self._temp_dir: str | None = None
        # Track the actual path being scanned (changes if ZIP is extracted)
        self._real_target_path = self.target_path

    def _validate_plugin_headers(self, path: str) -> bool:
        """
        Scan for WordPress plugin headers to verify the target is actually a plugin.
        Checks PHP file headers and readme.txt structures.
        """
        # Recursively walk the directory
        for root, _, files in os.walk(path):
            # Look for readme.txt file
            if "readme.txt" in files:
                # Build file path
                fpath = os.path.join(root, "readme.txt")
                # Read file safely
                content = _read_file_safe(fpath, max_bytes=PLUGIN_HEADER_READ_BYTES)
                # Search for WordPress readme headers
                if content and re.search(r"===\s*[\w\s]+\s*===", content):
                    # Found a valid readme
                    return True
            # Look for PHP file headers
            for fname in files:
                # Check extension
                if fname.endswith(".php"):
                    # Build file path
                    fpath = os.path.join(root, fname)
                    # Read file safely
                    content = _read_file_safe(fpath, max_bytes=PLUGIN_HEADER_READ_BYTES)
                    # Search for standard 'Plugin Name:' header
                    if content and re.search(r"Plugin Name:", content, re.IGNORECASE):
                        # Found a valid plugin file
                        return True
        # No headers found
        return False

    def _cleanup_temp_dir(self) -> None:
        """Delete any temporary extraction directory created during a ZIP scan."""
        # Skip cleanup when no temporary directory is active
        if not self._temp_dir:
            # Nothing to clean up
            return
        # Ignore filesystem cleanup failures to avoid masking scan errors
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        # Reset internal state after cleanup
        self._temp_dir = None

    def _plugin_name(self) -> str:
        """Return a friendly plugin name for reports based on the original target."""
        # Use the ZIP stem for archive scans so the report name is cleaner
        if self.target_path.lower().endswith(".zip"):
            # Drop the archive extension
            return Path(self.target_path).stem
        # Use the directory name for extracted plugins
        return os.path.basename(self.target_path)

    def _build_error_result(self, message: str) -> ScanResult:
        """Create a standard error result object for early-return failure paths."""
        # Build a minimal result payload with the intended plugin name
        result = ScanResult(
            plugin_path=self.target_path,
            plugin_name=self._plugin_name(),
            scan_mode="deep" if self.deep_scan else "standard",
        )
        # Record the user-facing error message
        result.errors.append(message)
        # Return the populated result
        return result

    def _extract_zip_safely(self, zip_path: str, destination: str) -> None:
        """Safely extract a ZIP archive while preventing Zip Slip and symlink abuse."""
        # Resolve the extraction root once for path traversal validation
        destination_root = Path(destination).resolve()
        # Track the total expanded size to limit decompression abuse
        total_uncompressed_size = 0

        # Open the archive for manual, validated extraction
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # Validate and extract each member independently
            for member in zip_ref.infolist():
                # Skip empty filenames that cannot be extracted meaningfully
                if not member.filename:
                    # Continue with the next entry
                    continue

                # Reject archives that expand to an unreasonable total size
                total_uncompressed_size += member.file_size
                if total_uncompressed_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    # Abort extraction before disk usage becomes excessive
                    raise ValueError("ZIP archive expands beyond the maximum safe size.")

                # Reject absolute archive paths outright
                if Path(member.filename).is_absolute():
                    # Prevent writing outside the temporary extraction root
                    raise ValueError("ZIP archive contains unsafe absolute paths.")

                # Resolve the final destination path for this member
                target_path = (destination_root / member.filename).resolve()
                try:
                    # Ensure the resolved path stays inside the extraction directory
                    target_path.relative_to(destination_root)
                except ValueError as exc:
                    # Abort when a path traversal entry is encountered
                    raise ValueError("ZIP archive contains unsafe path traversal entries.") from exc

                # Reject symlinks because they can be abused to escape the extraction root
                unix_mode = member.external_attr >> 16
                if unix_mode and (unix_mode & 0o170000) == 0o120000:
                    # Disallow symlink members entirely
                    raise ValueError("ZIP archive contains symbolic links, which are not supported.")

                # Create directories directly without opening them as files
                if member.is_dir():
                    # Ensure the directory exists
                    target_path.mkdir(parents=True, exist_ok=True)
                    # Continue after handling the directory entry
                    continue

                # Ensure the parent directory exists before writing the file
                target_path.parent.mkdir(parents=True, exist_ok=True)
                # Stream the file contents safely to disk
                with zip_ref.open(member, "r") as source, target_path.open("wb") as target_file:
                    # Copy the archive member without trusting extractall()
                    while chunk := source.read(1024 * 64):
                        # Write the current chunk to the extracted file
                        target_file.write(chunk)

    def _discover_files(self) -> tuple[list[str], list[str]]:
        """
        Find all files that meet the scanning criteria.
        Filters by extension, size, and exclusion lists.
        """
        # List for valid files
        scannable: list[str] = []
        # List for skipped files
        skipped: list[str] = []

        # Walk the directory tree
        for root, dirs, files in os.walk(self._real_target_path):
            # Modify dirs list to avoid walking into excluded folders
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]

            # Iterate through files in directory
            for fname in files:
                # Build absolute path
                fpath = os.path.join(root, fname)
                # Get extension
                ext = os.path.splitext(fname)[1].lower()

                # Skip known binary types
                if ext in BINARY_EXTENSIONS:
                    # Add to skipped list
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Continue loop
                    continue

                # Skip if extension is not in include list
                if ext not in self.include_extensions:
                    # Add to skipped list
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Continue loop
                    continue

                try:
                    # Get file size
                    size = os.path.getsize(fpath)
                except OSError:
                    # Skip if OS error
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Continue loop
                    continue

                # Skip files larger than the threshold
                if size > self.max_file_size:
                    # Add to skipped list
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Continue loop
                    continue

                # Skip empty files
                if size == 0:
                    # Add to skipped list
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Continue loop
                    continue

                # Add valid file to scan list
                scannable.append(fpath)

        # Return found and skipped files
        return scannable, skipped

    def _scan_file(self, fpath: str) -> tuple[FileInfo, list[Finding]]:
        """
        The core analysis logic for a single file.
        Detects language, calculates entropy, and runs pattern matching.
        """
        # Calculate relative path for reporting
        rel_path = os.path.relpath(fpath, self._real_target_path)
        # Get extension
        ext = os.path.splitext(fpath)[1].lower()
        # Detect language
        lang = _detect_language(ext)
        # Read file safely
        content = _read_file_safe(fpath)

        # Read raw bytes for checksum and entropy
        try:
            # Read the raw file bytes for hashing and entropy calculations
            raw = Path(fpath).read_bytes()
        except OSError as exc:
            # Raise a clearer error that the caller can surface in the result
            raise RuntimeError(f"Could not read file contents: {exc}") from exc
        # Calculate hash
        sha256 = hashlib.sha256(raw).hexdigest()
        # Calculate entropy
        entropy = _calculate_entropy(raw)

        # Handle binary or unreadable files
        if content is None:
            # Create minimal file info
            fi = FileInfo(
                path=fpath, relative_path=rel_path,
                size=len(raw), extension=ext, sha256=sha256,
                language=lang, lines=0, entropy=entropy,
            )
            # Return info with no findings
            return fi, []

        # Split content into lines
        lines = content.splitlines()
        # Create full file info
        fi = FileInfo(
            path=fpath, relative_path=rel_path,
            size=len(raw), extension=ext, sha256=sha256,
            language=lang, lines=len(lines), entropy=entropy,
        )

        # List to store results
        findings: list[Finding] = []
        # Filter patterns by language
        applicable_patterns = [
            p for p in self._patterns
            if lang in p.languages or (lang == "unknown" and "php" in p.languages)
        ]

        # Iterate through every signature
        for pattern in applicable_patterns:
            # Skip if severity is below threshold
            if pattern.severity < self.severity_threshold:
                # Continue loop
                continue

            try:
                # Compile regex pattern
                regex = re.compile(pattern.pattern, re.IGNORECASE)
            except re.error:
                # Skip invalid patterns
                continue

            # Iterate through every line in the file
            for i, line in enumerate(lines):
                # Search for match
                match = regex.search(line)
                # If a match is found
                if match:
                    # Logic to identify false positives by looking at nearby lines
                    is_fp = False
                    # Define start of context block
                    ctx_start = max(0, i - 10)
                    # Define end of context block
                    ctx_end = min(len(lines), i + 10)
                    # Join lines for regex context check
                    context_block = "\n".join(lines[ctx_start:ctx_end])

                    # Check patterns that negate the finding
                    for fp_pat in pattern.false_positive_patterns:
                        # Search context block
                        if re.search(fp_pat, context_block, re.IGNORECASE):
                            # Mark as false positive
                            is_fp = True
                            # Break inner loop
                            break

                    # Capture lines before finding
                    ctx_before = lines[max(0, i - self.context_lines):i]
                    # Capture lines after finding
                    ctx_after = lines[i + 1:i + 1 + self.context_lines]

                    # Create finding object
                    finding = Finding(
                        pattern=pattern,
                        file_path=rel_path,
                        line_number=i + 1,
                        match_column=match.start() + 1,
                        line_content=line.rstrip(),
                        context_before=ctx_before,
                        context_after=ctx_after,
                        false_positive=is_fp,
                    )
                    # Add to list
                    findings.append(finding)

        # Perform entropy analysis if deep scan is enabled
        if self.deep_scan and entropy > 6.0 and lang == "php":
            # Add an entropy finding
            findings.append(Finding(
                pattern=VulnPattern(
                    id="ENTROPY-001",
                    title="High entropy file (possible obfuscation)",
                    severity=Severity.MEDIUM,
                    pattern="",
                    description=(
                        f"File has unusually high entropy ({entropy:.2f}/8.0), "
                        "suggesting obfuscated or encoded content."
                    ),
                    cwe="CWE-506",
                    recommendation="Manually review this file for obfuscated malicious code.",
                    confidence="medium",
                ),
                file_path=rel_path,
                line_number=0,
                match_column=0,
                line_content=f"Entropy: {entropy:.4f}",
            ))

        # Return results
        return fi, findings

    def scan(self) -> ScanResult:
        """
        Perform the full scan procedure.
        Handles extraction, discovery, multi-threaded analysis, and cleanup.
        """
        # Reset real target path so repeated scans on the same instance are safe
        self._real_target_path = self.target_path
        # Initialize result object early so all return paths are consistent
        result = ScanResult(
            plugin_path=self.target_path,
            plugin_name=self._plugin_name(),
            scan_mode="deep" if self.deep_scan else "standard",
        )

        # Handle user-supplied .zip paths that are not actually valid ZIP files
        if self.target_path.lower().endswith(".zip") and not zipfile.is_zipfile(self.target_path):
            # Return a clear validation error instead of silently walking a file path
            return self._build_error_result("Invalid ZIP archive: The file is not a valid or readable ZIP.")

        # Extract ZIP archives into a temporary directory before scanning
        if zipfile.is_zipfile(self.target_path):
            # Create a temporary extraction root
            self._temp_dir = tempfile.mkdtemp(prefix="wpcheck_")
            try:
                # Extract the archive using path traversal and symlink protections
                self._extract_zip_safely(self.target_path, self._temp_dir)
                # Scan the extracted contents instead of the archive file itself
                self._real_target_path = self._temp_dir
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                # Clean up any partial extraction state before returning the error
                self._cleanup_temp_dir()
                # Return a user-friendly extraction error message
                return self._build_error_result(f"Failed to extract ZIP: {exc}")
        elif not os.path.isdir(self.target_path):
            # Refuse to scan unsupported target types
            return self._build_error_result("Target must be a directory or a valid .zip file.")

        # Ensure the extracted or on-disk target looks like a WordPress plugin
        if not self._validate_plugin_headers(self._real_target_path):
            # Clean up before returning the validation error
            self._cleanup_temp_dir()
            # Abort the scan with a clear explanation
            return self._build_error_result(
                "Invalid WordPress plugin: No 'Plugin Name:' header or valid readme.txt found."
            )

        # Discover scannable files and files that were skipped
        files, skipped = self._discover_files()

        # Store skipped files
        result.files_skipped = skipped

        # Handle empty scan list
        if not files:
            # Add error
            result.errors.append("No scannable files found in the target.")
            # Cleanup temp dir
            self._cleanup_temp_dir()
            # Return
            return result

        # Get timestamp
        start = time.time()

        # Execute analysis in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit scan tasks
            futures = {executor.submit(self._scan_file, f): f for f in files}
            # Process results as they complete
            for future in as_completed(futures):
                # Get path
                fpath = futures[future]
                try:
                    # Get result from thread
                    file_info, findings = future.result()
                    # Fix paths if scan was on extracted ZIP
                    if self._temp_dir:
                        # Calculate relative path
                        file_info.relative_path = os.path.relpath(fpath, self._temp_dir)
                        # Fix finding paths
                        for f in findings:
                            # Update path
                            f.file_path = file_info.relative_path

                    # Store info
                    result.files_scanned.append(file_info)
                    # Store findings
                    result.findings.extend(findings)
                except Exception as exc:
                    # Capture runtime errors
                    result.errors.append(f"Error scanning {os.path.relpath(fpath, self._real_target_path)}: {exc}")

        # Calculate final duration
        result.scan_duration = round(time.time() - start, 3)

        # Final cleanup of temp directory
        self._cleanup_temp_dir()

        # Sort all findings by severity, path, and line number
        result.findings.sort(key=lambda f: (-f.severity, f.file_path, f.line_number))

        # Return completed results
        return result
