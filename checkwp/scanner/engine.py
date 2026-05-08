"""Core scanning engine — orchestrates file discovery, pattern matching, and analysis."""

from __future__ import annotations

import os
import re
import hashlib
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Set
import zipfile
import tempfile
import shutil

import chardet

from checkwp.scanner.patterns import (
    ALL_PATTERNS,
    LANGUAGE_EXTENSIONS,
    Severity,
    VulnPattern,
)


@dataclass
class Finding:
    """A single vulnerability finding."""
    pattern: VulnPattern
    file_path: str
    line_number: int
    line_content: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    ai_analysis: Optional[str] = None
    ai_confirmed: Optional[bool] = None
    false_positive: bool = False

    @property
    def severity(self) -> Severity:
        return self.pattern.severity

    @property
    def relative_path(self) -> str:
        return self.file_path


@dataclass
class FileInfo:
    """Metadata about a scanned file."""
    path: str
    relative_path: str
    size: int
    extension: str
    sha256: str
    language: str
    lines: int
    entropy: float = 0.0


@dataclass
class ScanResult:
    """Complete scan results."""
    plugin_path: str
    plugin_name: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: List[FileInfo] = field(default_factory=list)
    files_skipped: List[str] = field(default_factory=list)
    scan_duration: float = 0.0
    ai_enabled: bool = False
    ai_model: str = ""
    ai_tokens: int = 0
    scan_mode: str = "standard"
    errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len([f for f in self.findings if not f.false_positive])

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.CRITICAL and not f.false_positive])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.HIGH and not f.false_positive])

    @property
    def medium_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.MEDIUM and not f.false_positive])

    @property
    def low_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.LOW and not f.false_positive])

    @property
    def info_count(self) -> int:
        return len([f for f in self.findings if f.severity == Severity.INFO and not f.false_positive])

    def grade(self) -> str:
        """Calculate overall security grade A+ through F."""
        score = 100
        for f in self.findings:
            if f.false_positive:
                continue
            if f.severity == Severity.CRITICAL:
                score -= 25
            elif f.severity == Severity.HIGH:
                score -= 12
            elif f.severity == Severity.MEDIUM:
                score -= 5
            elif f.severity == Severity.LOW:
                score -= 2
            elif f.severity == Severity.INFO:
                score -= 0.5
        score = max(0, score)
        if score >= 97:
            return "A+"
        elif score >= 93:
            return "A"
        elif score >= 90:
            return "A-"
        elif score >= 87:
            return "B+"
        elif score >= 83:
            return "B"
        elif score >= 80:
            return "B-"
        elif score >= 77:
            return "C+"
        elif score >= 73:
            return "C"
        elif score >= 70:
            return "C-"
        elif score >= 67:
            return "D+"
        elif score >= 63:
            return "D"
        elif score >= 60:
            return "D-"
        else:
            return "F"

    def grade_color(self) -> str:
        g = self.grade()
        if g.startswith("A"):
            return "#22c55e"
        elif g.startswith("B"):
            return "#3b82f6"
        elif g.startswith("C"):
            return "#eab308"
        elif g.startswith("D"):
            return "#f97316"
        return "#ef4444"


DEFAULT_EXCLUDE = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
    ".DS_Store", "Thumbs.db",
}

DEFAULT_EXTENSIONS = set()
for exts in LANGUAGE_EXTENSIONS.values():
    DEFAULT_EXTENSIONS.update(exts)

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
    """Calculate Shannon entropy of data (0-8 scale for bytes)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _detect_language(ext: str) -> str:
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    return "unknown"


def _read_file_safe(path: str) -> Optional[str]:
    """Read a file, handling encoding detection."""
    try:
        raw = Path(path).read_bytes()
        if b"\x00" in raw[:8192]:
            return None  # likely binary
        detected = chardet.detect(raw[:10000])
        encoding = detected.get("encoding") or "utf-8"
        try:
            return raw.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            return raw.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


class Scanner:
    """Main vulnerability scanner."""

    def __init__(
        self,
        target_path: str,
        *,
        severity_threshold: Severity = Severity.INFO,
        max_file_size_kb: int = 2048,
        exclude_dirs: Optional[Set[str]] = None,
        include_extensions: Optional[Set[str]] = None,
        deep_scan: bool = False,
        threads: int = 4,
        context_lines: int = 3,
    ):
        self.target_path = os.path.abspath(target_path)
        self.severity_threshold = severity_threshold
        self.max_file_size = max_file_size_kb * 1024
        self.exclude_dirs = exclude_dirs or DEFAULT_EXCLUDE
        self.include_extensions = include_extensions or DEFAULT_EXTENSIONS
        self.deep_scan = deep_scan
        self.threads = max(1, threads)
        self.context_lines = context_lines
        self._patterns = ALL_PATTERNS
        self._temp_dir = None
        self._real_target_path = self.target_path

    def _validate_plugin_headers(self, path: str) -> bool:
        """Check if any PHP file or readme.txt has a WordPress Plugin header."""
        for root, _, files in os.walk(path):
            # Check for readme.txt
            if "readme.txt" in files:
                fpath = os.path.join(root, "readme.txt")
                content = _read_file_safe(fpath)
                if content and re.search(r"===\s*[\w\s]+\s*===", content):
                    return True
            for fname in files:
                if fname.endswith(".php"):
                    fpath = os.path.join(root, fname)
                    content = _read_file_safe(fpath)
                    if content and re.search(r"Plugin Name:", content, re.IGNORECASE):
                        return True
        return False

    def _discover_files(self) -> tuple[List[str], List[str]]:
        """Walk directory tree and discover scannable files."""
        scannable: List[str] = []
        skipped: List[str] = []

        for root, dirs, files in os.walk(self.target_path):
            # Filter excluded directories in-place
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]

            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                if ext in BINARY_EXTENSIONS:
                    skipped.append(fpath)
                    continue

                if ext not in self.include_extensions:
                    skipped.append(fpath)
                    continue

                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    skipped.append(fpath)
                    continue

                if size > self.max_file_size:
                    skipped.append(fpath)
                    continue

                if size == 0:
                    skipped.append(fpath)
                    continue

                scannable.append(fpath)

        return scannable, skipped

    def _scan_file(self, fpath: str) -> tuple[FileInfo, List[Finding]]:
        """Scan a single file for vulnerabilities."""
        rel_path = os.path.relpath(fpath, self._real_target_path)
        ext = os.path.splitext(fpath)[1].lower()
        lang = _detect_language(ext)
        content = _read_file_safe(fpath)

        raw = Path(fpath).read_bytes()
        sha256 = hashlib.sha256(raw).hexdigest()
        entropy = _calculate_entropy(raw)

        if content is None:
            fi = FileInfo(
                path=fpath, relative_path=rel_path,
                size=len(raw), extension=ext, sha256=sha256,
                language=lang, lines=0, entropy=entropy,
            )
            return fi, []

        lines = content.splitlines()
        fi = FileInfo(
            path=fpath, relative_path=rel_path,
            size=len(raw), extension=ext, sha256=sha256,
            language=lang, lines=len(lines), entropy=entropy,
        )

        findings: List[Finding] = []
        applicable_patterns = [
            p for p in self._patterns
            if lang in p.languages or (lang == "unknown" and "php" in p.languages)
        ]

        for pattern in applicable_patterns:
            if pattern.severity < self.severity_threshold:
                continue

            try:
                regex = re.compile(pattern.pattern, re.IGNORECASE)
            except re.error:
                continue

            for i, line in enumerate(lines):
                if regex.search(line):
                    # Check false positive patterns in nearby context
                    is_fp = False
                    ctx_start = max(0, i - 10)
                    ctx_end = min(len(lines), i + 10)
                    context_block = "\n".join(lines[ctx_start:ctx_end])

                    for fp_pat in pattern.false_positive_patterns:
                        if re.search(fp_pat, context_block, re.IGNORECASE):
                            is_fp = True
                            break

                    ctx_before = lines[max(0, i - self.context_lines):i]
                    ctx_after = lines[i + 1:i + 1 + self.context_lines]

                    finding = Finding(
                        pattern=pattern,
                        file_path=rel_path,
                        line_number=i + 1,
                        line_content=line.rstrip(),
                        context_before=ctx_before,
                        context_after=ctx_after,
                        false_positive=is_fp,
                    )
                    findings.append(finding)

        # Deep scan: check for high-entropy files (possibly obfuscated)
        if self.deep_scan and entropy > 6.0 and lang == "php":
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
                line_content=f"Entropy: {entropy:.4f}",
            ))

        return fi, findings

    def scan(self) -> ScanResult:
        """Execute the full scan."""
        # Handle ZIP target
        if zipfile.is_zipfile(self.target_path):
            self._temp_dir = tempfile.mkdtemp(prefix="checkwp_")
            try:
                with zipfile.ZipFile(self.target_path, 'r') as zip_ref:
                    zip_ref.extractall(self._temp_dir)
                
                if not self._validate_plugin_headers(self._temp_dir):
                    shutil.rmtree(self._temp_dir)
                    result = ScanResult(plugin_path=self.target_path, plugin_name=os.path.basename(self.target_path))
                    result.errors.append("Invalid WordPress plugin: No 'Plugin Name:' header found in ZIP.")
                    return result
                
                # Update scanning target to extracted directory
                self._real_target_path = self._temp_dir
            except Exception as e:
                if self._temp_dir and os.path.exists(self._temp_dir):
                    shutil.rmtree(self._temp_dir)
                result = ScanResult(plugin_path=self.target_path, plugin_name=os.path.basename(self.target_path))
                result.errors.append(f"Failed to extract ZIP: {e}")
                return result

        plugin_name = os.path.basename(self.target_path)
        result = ScanResult(
            plugin_path=self.target_path,
            plugin_name=plugin_name,
            scan_mode="deep" if self.deep_scan else "standard",
        )

        # Discovery logic must use _real_target_path
        files: List[str] = []
        skipped: List[str] = []
        
        for root, dirs, fnames in os.walk(self._real_target_path):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for fname in fnames:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in BINARY_EXTENSIONS or ext not in self.include_extensions:
                    skipped.append(os.path.relpath(fpath, self._real_target_path))
                    continue
                try:
                    size = os.path.getsize(fpath)
                    if size > self.max_file_size or size == 0:
                        skipped.append(os.path.relpath(fpath, self._real_target_path))
                        continue
                    files.append(fpath)
                except OSError:
                    skipped.append(os.path.relpath(fpath, self._real_target_path))

        result.files_skipped = skipped

        if not files:
            result.errors.append("No scannable files found in the target.")
            if self._temp_dir and os.path.exists(self._temp_dir):
                shutil.rmtree(self._temp_dir)
            return result

        import time
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in files}
            for future in as_completed(futures):
                fpath = futures[future]
                try:
                    file_info, findings = future.result()
                    # Correct relative path for zip extraction
                    if self._temp_dir:
                        file_info.relative_path = os.path.relpath(fpath, self._temp_dir)
                        for f in findings:
                            f.file_path = file_info.relative_path
                            
                    result.files_scanned.append(file_info)
                    result.findings.extend(findings)
                except Exception as exc:
                    result.errors.append(f"Error scanning {os.path.relpath(fpath, self._real_target_path)}: {exc}")

        result.scan_duration = round(time.time() - start, 3)

        # Cleanup
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir)

        # Sort findings: highest severity first, then by file, then by line
        result.findings.sort(key=lambda f: (-f.severity, f.file_path, f.line_number))

        return result
