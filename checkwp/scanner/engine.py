"""
Core scanning engine — orchestrates file discovery, pattern matching, and analysis.
This module handles the heavy lifting of finding files, checking headers, and identifying vulnerabilities.
"""

# Import type annotations for compatibility
from __future__ import annotations

# Import OS module for path and directory operations
import os
# Import regex module for pattern matching
import re
# Import hashlib for file integrity checks
import hashlib
# Import math for entropy calculations
import math
# Import concurrent execution tools for multi-threading
from concurrent.futures import ThreadPoolExecutor, as_completed
# Import dataclasses for structured data models
from dataclasses import dataclass, field
# Import Path for filesystem interactions
from pathlib import Path
# Import typing for type hinting
from typing import List, Optional, Dict, Set
# Import zipfile for archive handling
import zipfile
# Import tempfile for temporary directory creation
import tempfile
# Import shutil for directory cleanup
import shutil

# Import chardet for character encoding detection
import chardet

# Import constants and severity enums from patterns module
from checkwp.scanner.patterns import (
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
    context_before: List[str] = field(default_factory=list)
    # Lines of code appearing after the finding for context
    context_after: List[str] = field(default_factory=list)
    # The analysis text provided by an AI model
    ai_analysis: Optional[str] = None
    # Whether an AI model confirmed the finding as a true positive
    ai_confirmed: Optional[bool] = None
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
    findings: List[Finding] = field(default_factory=list)
    # List of metadata for all successfully scanned files
    files_scanned: List[FileInfo] = field(default_factory=list)
    # List of file paths that were skipped during the scan
    files_skipped: List[str] = field(default_factory=list)
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
    errors: List[str] = field(default_factory=list)

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
DEFAULT_EXTENSIONS = set()
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
    freq: Dict[int, int] = {}
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


def _read_file_safe(path: str) -> Optional[str]:
    """
    Attempt to read a file with intelligent encoding detection.
    Skips binary files and handles decode errors gracefully.
    """
    try:
        # Read raw bytes from disk
        raw = Path(path).read_bytes()
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
        exclude_dirs: Optional[Set[str]] = None,
        include_extensions: Optional[Set[str]] = None,
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
        self.exclude_dirs = exclude_dirs or DEFAULT_EXCLUDE
        # Set included extensions or use defaults
        self.include_extensions = include_extensions or DEFAULT_EXTENSIONS
        # Toggle entropy analysis
        self.deep_scan = deep_scan
        # Cap threads to at least 1
        self.threads = max(1, threads)
        # Number of surrounding code lines to capture
        self.context_lines = context_lines
        # Load all vulnerability signatures
        self._patterns = ALL_PATTERNS
        # Initialize temp directory tracker
        self._temp_dir = None
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
                content = _read_file_safe(fpath)
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
                    content = _read_file_safe(fpath)
                    # Search for standard 'Plugin Name:' header
                    if content and re.search(r"Plugin Name:", content, re.IGNORECASE):
                        # Found a valid plugin file
                        return True
        # No headers found
        return False

    def _discover_files(self) -> tuple[List[str], List[str]]:
        """
        Find all files that meet the scanning criteria.
        Filters by extension, size, and exclusion lists.
        """
        # List for valid files
        scannable: List[str] = []
        # List for skipped files
        skipped: List[str] = []

        # Walk the directory tree
        for root, dirs, files in os.walk(self.target_path):
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
                    skipped.append(fpath)
                    # Continue loop
                    continue

                # Skip if extension is not in include list
                if ext not in self.include_extensions:
                    # Add to skipped list
                    skipped.append(fpath)
                    # Continue loop
                    continue

                try:
                    # Get file size
                    size = os.path.getsize(fpath)
                except OSError:
                    # Skip if OS error
                    skipped.append(fpath)
                    # Continue loop
                    continue

                # Skip files larger than the threshold
                if size > self.max_file_size:
                    # Add to skipped list
                    skipped.append(fpath)
                    # Continue loop
                    continue

                # Skip empty files
                if size == 0:
                    # Add to skipped list
                    skipped.append(fpath)
                    # Continue loop
                    continue

                # Add valid file to scan list
                scannable.append(fpath)

        # Return found and skipped files
        return scannable, skipped

    def _scan_file(self, fpath: str) -> tuple[FileInfo, List[Finding]]:
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
        raw = Path(fpath).read_bytes()
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
        findings: List[Finding] = []
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
                    description=f"File has unusually high entropy ({entropy:.2f}/8.0), suggesting obfuscated or encoded content.",
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
        # Determine if target is a ZIP file
        if zipfile.is_zipfile(self.target_path):
            # Create temp directory
            self._temp_dir = tempfile.mkdtemp(prefix="checkwp_")
            try:
                # Open zip archive
                with zipfile.ZipFile(self.target_path, 'r') as zip_ref:
                    # Extract all files
                    zip_ref.extractall(self._temp_dir)
                
                # Check for WordPress plugin markers
                if not self._validate_plugin_headers(self._temp_dir):
                    # Delete temp dir
                    shutil.rmtree(self._temp_dir)
                    # Create empty result
                    result = ScanResult(plugin_path=self.target_path, plugin_name=os.path.basename(self.target_path))
                    # Add validation error
                    result.errors.append("Invalid WordPress plugin: No 'Plugin Name:' header found in ZIP.")
                    # Abort and return
                    return result
                
                # Set real target to extracted path
                self._real_target_path = self._temp_dir
            except Exception as e:
                # Cleanup temp dir on error
                if self._temp_dir and os.path.exists(self._temp_dir):
                    # Delete temp dir
                    shutil.rmtree(self._temp_dir)
                # Create empty result
                result = ScanResult(plugin_path=self.target_path, plugin_name=os.path.basename(self.target_path))
                # Add extraction error
                result.errors.append(f"Failed to extract ZIP: {e}")
                # Abort and return
                return result

        # Get base name for plugin
        plugin_name = os.path.basename(self.target_path)
        # Initialize result object
        result = ScanResult(
            plugin_path=self.target_path,
            plugin_name=plugin_name,
            scan_mode="deep" if self.deep_scan else "standard",
        )

        # Lists for file discovery
        files: List[str] = []
        # Lists for skipped files
        skipped: List[str] = []
        
        # Traverse filesystem
        for root, dirs, fnames in os.walk(self._real_target_path):
            # In-place directory filtering
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            # Iterate through files
            for fname in fnames:
                # Absolute path
                fpath = os.path.join(root, fname)
                # Extension
                ext = os.path.splitext(fname)[1].lower()
                # Filter by extension
                if ext in BINARY_EXTENSIONS or ext not in self.include_extensions:
                    # Mark as skipped
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    # Skip
                    continue
                try:
                    # Get size
                    size = os.path.getsize(fpath)
                    # Filter by size
                    if size > self.max_file_size or size == 0:
                        # Mark as skipped
                        skipped.append(os.path.relpath(fpath, self._real_target_path))
                        # Skip
                        continue
                    # Add to scan list
                    files.append(fpath)
                except OSError:
                    # Skip on error
                    skipped.append(os.path.relpath(fpath, self._real_target_path))

        # Store skipped files
        result.files_skipped = skipped

        # Handle empty scan list
        if not files:
            # Add error
            result.errors.append("No scannable files found in the target.")
            # Cleanup temp dir
            if self._temp_dir and os.path.exists(self._temp_dir):
                # Delete
                shutil.rmtree(self._temp_dir)
            # Return
            return result

        # Record start time
        import time
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
        if self._temp_dir and os.path.exists(self._temp_dir):
            # Delete directory
            shutil.rmtree(self._temp_dir)

        # Sort all findings by severity, path, and line number
        result.findings.sort(key=lambda f: (-f.severity, f.file_path, f.line_number))

        # Return completed results
        return result
