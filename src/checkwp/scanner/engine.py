"""
Core scanning engine — orchestrates file discovery, pattern matching, and analysis.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import tempfile
import time
import zipfile
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import chardet
except ImportError:  # pragma: no cover - exercised when chardet is unavailable
    class _ChardetFallback:
        @staticmethod
        def detect(data: bytes) -> dict[str, str | None]:
            try:
                data.decode("utf-8")
                return {"encoding": "utf-8"}
            except UnicodeDecodeError:
                return {"encoding": None}


    chardet: Any = _ChardetFallback()

from checkwp.scanner.patterns import ALL_PATTERNS, LANGUAGE_EXTENSIONS, Severity, VulnPattern


@dataclass
class Finding:
    """Represents a single vulnerability finding identified during a scan."""

    pattern: VulnPattern
    file_path: str
    line_number: int
    match_column: int
    line_content: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    ai_analysis: str | None = None
    ai_confirmed: bool | None = None
    false_positive: bool = False

    @property
    def severity(self) -> Severity:
        return self.pattern.severity

    @property
    def relative_path(self) -> str:
        return self.file_path


@dataclass
class FileInfo:
    """Metadata about a specific file scanned by the engine."""

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
    """Aggregates all findings, file metadata, and scan execution statistics."""

    plugin_path: str
    plugin_name: str
    plugin_version: str = ""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: list[FileInfo] = field(default_factory=list)
    files_skipped: list[str] = field(default_factory=list)
    scan_duration: float = 0.0
    ai_enabled: bool = False
    ai_model: str = ""
    ai_tokens: int = 0
    scan_mode: str = "standard"
    errors: list[str] = field(default_factory=list)

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
        return 0

    def grade(self) -> str:
        score = 100
        for finding in self.findings:
            if finding.false_positive:
                continue
            if finding.severity == Severity.CRITICAL:
                score -= 25
            elif finding.severity == Severity.HIGH:
                score -= 12
            elif finding.severity == Severity.MEDIUM:
                score -= 5
            elif finding.severity == Severity.LOW:
                score -= 2

        score = max(0, score)
        if score >= 97:
            return "A+"
        if score >= 93:
            return "A"
        if score >= 90:
            return "A-"
        if score >= 87:
            return "B+"
        if score >= 83:
            return "B"
        if score >= 80:
            return "B-"
        if score >= 77:
            return "C+"
        if score >= 73:
            return "C"
        if score >= 70:
            return "C-"
        if score >= 67:
            return "D+"
        if score >= 63:
            return "D"
        if score >= 60:
            return "D-"
        return "F"

    def grade_color(self) -> str:
        grade = self.grade()
        if grade.startswith("A"):
            return "#22c55e"
        if grade.startswith("B"):
            return "#3b82f6"
        if grade.startswith("C"):
            return "#eab308"
        if grade.startswith("D"):
            return "#f97316"
        return "#ef4444"


DEFAULT_EXCLUDE = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".DS_Store",
    "Thumbs.db",
}

DEFAULT_EXTENSIONS: set[str] = set()
for extensions in LANGUAGE_EXTENSIONS.values():
    DEFAULT_EXTENSIONS.update(extensions)

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".pdf",
    ".doc",
    ".docx",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".mo",
}

MAX_TEXT_READ_BYTES = 2 * 1024 * 1024
PLUGIN_HEADER_READ_BYTES = 64 * 1024
MAX_ZIP_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_MATCHES_PER_PATTERN_PER_FILE = 100

PLUGIN_NAME_RE = re.compile(r"(?im)^[ \t/*#@]*Plugin Name:\s*(?P<name>.+?)\s*$")
PLUGIN_VERSION_RE = re.compile(r"(?im)^[ \t/*#@]*(?:Version|Stable tag):\s*(?P<version>.+?)\s*$")
READMETXT_HEADER_RE = re.compile(r"^===\s*(?P<name>[^=\n]+?)\s*===$")

HEURISTIC_OBFUSCATION_RE = re.compile(
    r"\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|hex2bin|pack\s*\(\s*['\"]H\*['\"])\s*\(",
    re.IGNORECASE,
)
HEURISTIC_EXECUTION_RE = re.compile(
    r"\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|call_user_func(?:_array)?)\s*\(",
    re.IGNORECASE,
)
HEURISTIC_ERROR_SUPPRESSION_RE = re.compile(
    r"@\s*(?:eval|assert|system|exec|passthru|shell_exec|base64_decode|gzinflate|create_function)\s*\(",
    re.IGNORECASE,
)
HEURISTIC_LONG_BASE64_RE = re.compile(r"['\"][A-Za-z0-9+/]{140,}={0,2}['\"]")
HEURISTIC_CHR_CHAIN_RE = re.compile(r"(?:chr\s*\(\s*\d+\s*\)\s*\.?\s*){8,}", re.IGNORECASE)
HEURISTIC_VARIABLE_ROUTER_RE = re.compile(
    r"(?:\$\$\w+|\$\w+\s*=\s*\$\$\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)",
    re.IGNORECASE,
)
HEURISTIC_LINE_LENGTH_THRESHOLD = 500


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequencies: dict[int, int] = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _detect_language(ext: str) -> str:
    for language, extensions in LANGUAGE_EXTENSIONS.items():
        if ext in extensions:
            return language
    return "unknown"


def _decode_text(raw: bytes, *, max_bytes: int = MAX_TEXT_READ_BYTES) -> str | None:
    sample = raw[: max_bytes + 1][:max_bytes]
    if not sample:
        return ""
    if b"\x00" in sample[:8192]:
        return None

    try:
        return sample.decode("utf-8")
    except UnicodeDecodeError:
        detected = chardet.detect(sample[:10000])
        encoding = detected.get("encoding") or "utf-8"
        try:
            return sample.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError):
            return sample.decode("utf-8", errors="replace")


def _build_line_index(content: str) -> tuple[list[str], list[int]]:
    raw_lines = content.splitlines(keepends=True)
    if not raw_lines:
        return [""], [0]

    lines: list[str] = []
    line_starts: list[int] = []
    cursor = 0
    for raw_line in raw_lines:
        line_starts.append(cursor)
        lines.append(raw_line.rstrip("\r\n"))
        cursor += len(raw_line)
    return lines, line_starts


class Scanner:
    """Main coordinator for WordPress plugin security scans."""

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
        self.target_path = os.path.abspath(target_path)
        self.severity_threshold = severity_threshold
        self.max_file_size = max_file_size_kb * 1024
        self.exclude_dirs = set(exclude_dirs) if exclude_dirs is not None else set(DEFAULT_EXCLUDE)
        self.include_extensions = (
            {ext.lower() for ext in include_extensions}
            if include_extensions is not None
            else set(DEFAULT_EXTENSIONS)
        )
        self.deep_scan = deep_scan
        self.threads = max(1, threads)
        self.context_lines = max(0, context_lines)
        self._temp_dir: str | None = None
        self._real_target_path = self.target_path
        self._plugin_display_name = ""
        self._plugin_version = ""
        self._compiled_patterns: list[tuple[VulnPattern, re.Pattern[str]]] = []
        for pattern in ALL_PATTERNS:
            source = pattern.pattern if pattern.is_regex else re.escape(pattern.pattern)
            try:
                compiled = re.compile(source, re.IGNORECASE | re.MULTILINE)
            except re.error:
                continue
            self._compiled_patterns.append((pattern, compiled))

    def _validate_plugin_headers(self, path: str) -> bool:
        name, version, error = self._read_plugin_metadata(path)
        if error is not None:
            return False
        self._plugin_display_name = name or ""
        self._plugin_version = version or ""
        return True

    def _read_plugin_metadata(self, path: str) -> tuple[str | None, str | None, str | None]:
        readme_name, readme_version = self._read_readme_metadata(path)
        if readme_name:
            return readme_name, readme_version, None

        header_name, header_version = self._read_php_plugin_header(path)
        if header_name:
            return header_name, header_version, None

        return None, None, (
            "Invalid WordPress plugin: could not find a valid readme.txt header or PHP Plugin Name header."
        )

    def _read_readme_metadata(self, path: str) -> tuple[str | None, str | None]:
        readme_candidates: list[Path] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in self.exclude_dirs)
            if "readme.txt" in files:
                readme_candidates.append(Path(root) / "readme.txt")

        for readme_path in sorted(readme_candidates, key=lambda candidate: (len(candidate.parts), str(candidate))):
            try:
                raw = readme_path.read_bytes()
            except OSError:
                continue
            content = _decode_text(raw[:PLUGIN_HEADER_READ_BYTES], max_bytes=PLUGIN_HEADER_READ_BYTES)
            if not content:
                continue

            header_name: str | None = None
            for line in content.splitlines():
                stripped = line.lstrip("\ufeff").strip()
                if not stripped:
                    continue
                match = READMETXT_HEADER_RE.match(stripped)
                if match:
                    header_name = re.sub(r"\s+", " ", match.group("name").strip())
                break

            if not header_name:
                continue

            version_match = PLUGIN_VERSION_RE.search(content)
            return header_name, version_match.group("version").strip() if version_match else None

        return None, None

    def _read_php_plugin_header(self, path: str) -> tuple[str | None, str | None]:
        candidates: list[Path] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in self.exclude_dirs)
            for file_name in sorted(files):
                if file_name.lower().endswith((".php", ".inc", ".module")):
                    candidates.append(Path(root) / file_name)

        candidates.sort(key=lambda candidate: (len(candidate.relative_to(path).parts), str(candidate)))
        for php_path in candidates:
            try:
                raw = php_path.read_bytes()
            except OSError:
                continue
            content = _decode_text(raw[:PLUGIN_HEADER_READ_BYTES], max_bytes=PLUGIN_HEADER_READ_BYTES)
            if not content:
                continue
            name_match = PLUGIN_NAME_RE.search(content)
            if not name_match:
                continue
            version_match = PLUGIN_VERSION_RE.search(content)
            return name_match.group("name").strip(), version_match.group("version").strip() if version_match else None
        return None, None

    def _cleanup_temp_dir(self) -> None:
        if not self._temp_dir:
            return
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None

    def _plugin_name(self) -> str:
        if self._plugin_display_name:
            return self._plugin_display_name
        if self.target_path.lower().endswith(".zip"):
            return Path(self.target_path).stem
        return os.path.basename(self.target_path)

    def _build_error_result(self, message: str) -> ScanResult:
        result = ScanResult(
            plugin_path=self.target_path,
            plugin_name=self._plugin_name(),
            plugin_version=self._plugin_version,
            scan_mode="deep" if self.deep_scan else "standard",
        )
        result.errors.append(message)
        return result

    def _extract_zip_safely(self, zip_path: str, destination: str) -> None:
        destination_root = Path(destination).resolve()
        total_uncompressed_size = 0

        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in archive.infolist():
                if not member.filename:
                    continue

                total_uncompressed_size += member.file_size
                if total_uncompressed_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise ValueError("ZIP archive expands beyond the maximum safe size.")

                if Path(member.filename).is_absolute():
                    raise ValueError("ZIP archive contains unsafe absolute paths.")

                target_path = (destination_root / member.filename).resolve()
                try:
                    target_path.relative_to(destination_root)
                except ValueError as exc:
                    raise ValueError("ZIP archive contains unsafe path traversal entries.") from exc

                unix_mode = member.external_attr >> 16
                if unix_mode and (unix_mode & 0o170000) == 0o120000:
                    raise ValueError("ZIP archive contains symbolic links, which are not supported.")

                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target_path.open("wb") as target_file:
                    while chunk := source.read(1024 * 64):
                        target_file.write(chunk)

    def _discover_files(self) -> tuple[list[str], list[str]]:
        scannable: list[str] = []
        skipped: list[str] = []

        for root, dirs, files in os.walk(self._real_target_path):
            dirs[:] = sorted(d for d in dirs if d not in self.exclude_dirs)
            for file_name in sorted(files):
                file_path = os.path.join(root, file_name)
                relative_path = os.path.relpath(file_path, self._real_target_path)
                extension = os.path.splitext(file_name)[1].lower()

                if extension in BINARY_EXTENSIONS or extension not in self.include_extensions:
                    skipped.append(relative_path)
                    continue

                try:
                    size = os.path.getsize(file_path)
                except OSError:
                    skipped.append(relative_path)
                    continue

                if size == 0 or size > self.max_file_size:
                    skipped.append(relative_path)
                    continue

                scannable.append(file_path)

        scannable.sort()
        skipped.sort()
        return scannable, skipped

    def _finding_from_match(
        self,
        *,
        pattern: VulnPattern,
        match_start: int,
        line_index: list[int],
        lines: list[str],
        content: str,
        relative_path: str,
    ) -> Finding:
        line_idx = max(0, bisect_right(line_index, match_start) - 1)
        line_idx = min(line_idx, len(lines) - 1)
        line_start = line_index[line_idx]
        line_content = lines[line_idx]
        context_before = lines[max(0, line_idx - self.context_lines):line_idx]
        context_after = lines[line_idx + 1:line_idx + 1 + self.context_lines]
        fp_context = "\n".join(lines[max(0, line_idx - 10):min(len(lines), line_idx + 11)])
        false_positive = any(
            re.search(fp_pattern, fp_context, re.IGNORECASE) for fp_pattern in pattern.false_positive_patterns
        )

        return Finding(
            pattern=pattern,
            file_path=relative_path,
            line_number=line_idx + 1,
            match_column=(match_start - line_start) + 1,
            line_content=line_content.rstrip(),
            context_before=context_before,
            context_after=context_after,
            false_positive=false_positive,
        )

    def _heuristic_malware_findings(
        self,
        *,
        relative_path: str,
        language: str,
        content: str,
        lines: list[str],
        line_index: list[int],
        entropy: float,
    ) -> list[Finding]:
        if language != "php":
            return []

        score = 0
        signals: list[str] = []
        positions: list[int] = []

        if match := HEURISTIC_OBFUSCATION_RE.search(content):
            score += 2
            signals.append("payload decoding")
            positions.append(match.start())
        if match := HEURISTIC_EXECUTION_RE.search(content):
            score += 2
            signals.append("dynamic execution")
            positions.append(match.start())
        if match := HEURISTIC_ERROR_SUPPRESSION_RE.search(content):
            score += 1
            signals.append("error suppression")
            positions.append(match.start())
        if match := HEURISTIC_LONG_BASE64_RE.search(content):
            score += 2
            signals.append("long encoded blob")
            positions.append(match.start())
        if match := HEURISTIC_CHR_CHAIN_RE.search(content):
            score += 1
            signals.append("chr() string building")
            positions.append(match.start())
        if match := HEURISTIC_VARIABLE_ROUTER_RE.search(content):
            score += 1
            signals.append("variable-variable routing")
            positions.append(match.start())
        if entropy >= 6.1:
            score += 1
            signals.append(f"high entropy {entropy:.2f}")
        if any(len(line) >= HEURISTIC_LINE_LENGTH_THRESHOLD for line in lines):
            score += 1
            signals.append("very long line payload")

        if score < 4:
            return []

        severity = Severity.CRITICAL if score >= 6 else Severity.HIGH
        first_position = min(positions) if positions else 0
        pattern = VulnPattern(
            id="PHP-MALWARE-HEUR-001",
            title="Composite malware heuristic triggered",
            severity=severity,
            pattern="",
            description=(
                "The offline scanner detected a suspicious combination of obfuscation and execution indicators in the same file: "
                + ", ".join(signals[:5])
                + "."
            ),
            impact=(
                "Files that combine payload decoding, dynamic execution, and heavy obfuscation are commonly used as WordPress backdoors, spam injectors, or webshells."
            ),
            cwe="CWE-506",
            recommendation="Review the full file, decode hidden payloads, and remove the plugin if the behavior is not explicitly intended.",
            confidence="medium",
        )
        return [
            self._finding_from_match(
                pattern=pattern,
                match_start=first_position,
                line_index=line_index,
                lines=lines,
                content=content,
                relative_path=relative_path,
            )
        ]

    def _scan_file(self, file_path: str) -> tuple[FileInfo, list[Finding]]:
        relative_path = os.path.relpath(file_path, self._real_target_path)
        extension = os.path.splitext(file_path)[1].lower()
        language = _detect_language(extension)

        try:
            raw = Path(file_path).read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Could not read file contents: {exc}") from exc

        sha256 = hashlib.sha256(raw).hexdigest()
        entropy = _calculate_entropy(raw)
        content = _decode_text(raw)

        if content is None:
            file_info = FileInfo(
                path=file_path,
                relative_path=relative_path,
                size=len(raw),
                extension=extension,
                sha256=sha256,
                language=language,
                lines=0,
                entropy=entropy,
            )
            return file_info, []

        lines, line_index = _build_line_index(content)
        file_info = FileInfo(
            path=file_path,
            relative_path=relative_path,
            size=len(raw),
            extension=extension,
            sha256=sha256,
            language=language,
            lines=len(lines),
            entropy=entropy,
        )

        findings: list[Finding] = []
        seen: set[tuple[str, int, int]] = set()
        applicable_patterns = [
            (pattern, regex)
            for pattern, regex in self._compiled_patterns
            if pattern.severity >= self.severity_threshold
               and (language in pattern.languages or (language == "unknown" and "php" in pattern.languages))
        ]

        for pattern, regex in applicable_patterns:
            match_count = 0
            for match in regex.finditer(content):
                finding = self._finding_from_match(
                    pattern=pattern,
                    match_start=match.start(),
                    line_index=line_index,
                    lines=lines,
                    content=content,
                    relative_path=relative_path,
                )
                dedupe_key = (finding.pattern.id, finding.line_number, finding.match_column)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                findings.append(finding)
                match_count += 1
                if match_count >= MAX_MATCHES_PER_PATTERN_PER_FILE:
                    break

        findings.extend(
            finding
            for finding in self._heuristic_malware_findings(
                relative_path=relative_path,
                language=language,
                content=content,
                lines=lines,
                line_index=line_index,
                entropy=entropy,
            )
            if (finding.pattern.id, finding.line_number, finding.match_column) not in seen
        )

        if self.deep_scan and entropy > 6.0 and language == "php":
            findings.append(
                Finding(
                    pattern=VulnPattern(
                        id="ENTROPY-001",
                        title="High entropy file (possible obfuscation)",
                        severity=Severity.MEDIUM,
                        pattern="",
                        description=(
                            f"File has unusually high entropy ({entropy:.2f}/8.0), suggesting obfuscated or encoded content."
                        ),
                        cwe="CWE-506",
                        recommendation="Manually review this file for obfuscated malicious code.",
                        confidence="medium",
                    ),
                    file_path=relative_path,
                    line_number=0,
                    match_column=0,
                    line_content=f"Entropy: {entropy:.4f}",
                )
            )

        return file_info, findings

    def scan(self) -> ScanResult:
        self._real_target_path = self.target_path
        self._plugin_display_name = ""
        self._plugin_version = ""

        if self.target_path.lower().endswith(".zip") and not zipfile.is_zipfile(self.target_path):
            return self._build_error_result("Invalid ZIP archive: The file is not a valid or readable ZIP.")

        try:
            if zipfile.is_zipfile(self.target_path):
                self._temp_dir = tempfile.mkdtemp(prefix="checkwp_")
                self._extract_zip_safely(self.target_path, self._temp_dir)
                self._real_target_path = self._temp_dir
            elif not os.path.isdir(self.target_path):
                return self._build_error_result("Target must be a directory or a valid .zip file.")

            if not self._validate_plugin_headers(self._real_target_path):
                return self._build_error_result(
                    "Invalid WordPress plugin: could not find a valid readme.txt header or PHP Plugin Name header."
                )

            result = ScanResult(
                plugin_path=self.target_path,
                plugin_name=self._plugin_name(),
                plugin_version=self._plugin_version,
                scan_mode="deep" if self.deep_scan else "standard",
            )

            files, skipped = self._discover_files()
            result.files_skipped = skipped
            if not files:
                result.errors.append("No scannable files found in the target.")
                return result

            start = time.time()
            max_workers = min(self.threads, len(files))
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(self._scan_file, file_path): file_path for file_path in files}
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        file_info, findings = future.result()
                    except Exception as exc:
                        relative_path = os.path.relpath(file_path, self._real_target_path)
                        result.errors.append(f"Error scanning {relative_path}: {exc}")
                        continue

                    result.files_scanned.append(file_info)
                    result.findings.extend(findings)

            result.scan_duration = round(time.time() - start, 3)
            result.files_scanned.sort(key=lambda item: item.relative_path)
            result.findings.sort(key=lambda finding: (-finding.severity, finding.file_path, finding.line_number))
            return result
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            message = f"Failed to extract ZIP: {exc}" if zipfile.is_zipfile(self.target_path) else str(exc)
            return self._build_error_result(message)
        finally:
            self._cleanup_temp_dir()
