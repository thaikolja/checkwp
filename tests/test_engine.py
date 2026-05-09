"""Regression tests for the core scanner engine."""

import os
import zipfile

from checkwp.scanner.engine import Finding, Scanner, ScanResult, Severity
from checkwp.scanner.patterns import VulnPattern


def test_scanner_finds_vulnerabilities(vulnerable_plugin):
    scanner = Scanner(vulnerable_plugin)
    result = scanner.scan()

    # We expect 3 vulnerabilities based on vulnerable_plugin fixture
    assert result.total_findings >= 3

    # Check for specific types
    ids = [f.pattern.id for f in result.findings]
    assert any("RCE" in rule_id for rule_id in ids)
    assert any("SQLI" in rule_id for rule_id in ids)
    assert any("XSS" in rule_id for rule_id in ids)


def test_scanner_severity_filter(vulnerable_plugin):
    # Only scan for CRITICAL
    scanner = Scanner(vulnerable_plugin, severity_threshold=Severity.CRITICAL)
    result = scanner.scan()

    # eval($_GET['cmd']) should be critical
    assert result.total_findings > 0
    for finding in result.findings:
        assert finding.severity == Severity.CRITICAL


def test_invalid_plugin_fails(temp_plugin_dir):
    # Remove the plugin header file so the directory is no longer a valid plugin
    os.remove(os.path.join(temp_plugin_dir, "test-plugin.php"))

    scanner = Scanner(temp_plugin_dir)
    result = scanner.scan()

    # Invalid plugin directories should fail with a clear validation error
    assert result.total_findings == 0
    assert result.errors == [
        "Invalid WordPress plugin: No 'Plugin Name:' header or valid readme.txt found."
    ]


def test_invalid_zip_reports_error(tmp_path):
    invalid_zip = tmp_path / "broken.zip"
    invalid_zip.write_text("not a zip archive", encoding="utf-8")

    result = Scanner(str(invalid_zip)).scan()

    assert result.total_findings == 0
    assert result.errors == ["Invalid ZIP archive: The file is not a valid or readable ZIP."]


def test_zip_slip_archive_is_rejected(tmp_path):
    archive_path = tmp_path / "zip-slip.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../evil.php", "<?php echo 'owned';")
        archive.writestr("plugin.php", "<?php\n/*\nPlugin Name: Evil Plugin\n*/\n")

    result = Scanner(str(archive_path)).scan()

    assert result.total_findings == 0
    assert result.errors
    assert "unsafe path traversal entries" in result.errors[0]


def test_rest_route_permission_callback_signature(temp_plugin_dir):
    rest_route = os.path.join(temp_plugin_dir, "rest.php")
    with open(rest_route, "w", encoding="utf-8") as file_obj:
        file_obj.write(
            "<?php\n"
            "register_rest_route('checkwp/v1', '/sync', ['permission_callback' => '__return_true']);\n"
        )

    result = Scanner(temp_plugin_dir).scan()

    assert any(f.pattern.id == "PHP-AUTH-003" for f in result.findings)


def test_grade_ignores_false_positives():
    critical_pattern = VulnPattern(
        id="TEST-CRIT-001",
        title="Critical test finding",
        severity=Severity.CRITICAL,
        pattern=r"eval",
        description="Test pattern",
    )
    low_pattern = VulnPattern(
        id="TEST-LOW-001",
        title="Low test finding",
        severity=Severity.LOW,
        pattern=r"echo",
        description="Test pattern",
    )
    result = ScanResult(
        plugin_path="plugin",
        plugin_name="plugin",
        findings=[
            Finding(
                pattern=critical_pattern,
                file_path="plugin.php",
                line_number=1,
                match_column=1,
                line_content="eval($code);",
            ),
            Finding(
                pattern=low_pattern,
                file_path="plugin.php",
                line_number=2,
                match_column=1,
                line_content="echo $value;",
                false_positive=True,
            ),
        ],
    )

    assert result.total_findings == 1
    assert result.grade() == "C"


def test_discover_files_skips_binary_empty_and_large_files(temp_plugin_dir):
    binary_file = os.path.join(temp_plugin_dir, "image.png")
    with open(binary_file, "wb") as file_obj:
        file_obj.write(b"\x89PNG\r\n\x1a\n")

    empty_php = os.path.join(temp_plugin_dir, "empty.php")
    open(empty_php, "w", encoding="utf-8").close()

    large_php = os.path.join(temp_plugin_dir, "large.php")
    with open(large_php, "w", encoding="utf-8") as file_obj:
        file_obj.write("<?php\n" + "A" * 4096)

    scanner = Scanner(temp_plugin_dir, max_file_size_kb=1)
    result = scanner.scan()

    assert result.errors == []
    assert "image.png" in result.files_skipped
    assert "empty.php" in result.files_skipped
    assert "large.php" in result.files_skipped


