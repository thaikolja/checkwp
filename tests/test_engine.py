"""Regression tests for the core scanner engine."""

import os
import zipfile

from checkwp.scanner.engine import Finding, Scanner, ScanResult, Severity
from checkwp.scanner.patterns import VulnPattern

INVALID_PLUGIN_ERROR = "Invalid WordPress plugin: could not find a valid readme.txt header or PHP Plugin Name header."


def test_scanner_finds_vulnerabilities(vulnerable_plugin):
    result = Scanner(vulnerable_plugin).scan()

    assert result.total_findings >= 3
    ids = [finding.pattern.id for finding in result.findings]
    assert any("RCE" in rule_id for rule_id in ids)
    assert any("SQLI" in rule_id for rule_id in ids)
    assert any("XSS" in rule_id for rule_id in ids)


def test_scanner_severity_filter(vulnerable_plugin):
    result = Scanner(vulnerable_plugin, severity_threshold=Severity.CRITICAL).scan()

    assert result.total_findings > 0
    for finding in result.findings:
        assert finding.severity == Severity.CRITICAL


def test_invalid_plugin_fails(temp_plugin_dir):
    os.remove(os.path.join(temp_plugin_dir, "readme.txt"))
    with open(os.path.join(temp_plugin_dir, "test-plugin.php"), "w", encoding="utf-8") as file_obj:
        file_obj.write("<?php\n// no plugin header\n")

    result = Scanner(temp_plugin_dir).scan()

    assert result.total_findings == 0
    assert result.errors == [INVALID_PLUGIN_ERROR]


def test_plugin_header_without_readme_is_accepted(temp_plugin_dir):
    os.remove(os.path.join(temp_plugin_dir, "readme.txt"))

    result = Scanner(temp_plugin_dir).scan()

    assert result.errors == []
    assert result.plugin_name == "Test Plugin"


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


def test_zip_plugin_header_fallback_is_supported(tmp_path):
    archive_path = tmp_path / "plugin-header-only.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("plugin.php", "<?php\n/*\nPlugin Name: Zip Plugin\nVersion: 2.4.0\n*/\n")

    result = Scanner(str(archive_path)).scan()

    assert result.errors == []
    assert result.plugin_name == "Zip Plugin"
    assert result.plugin_version == "2.4.0"


def test_zip_plugin_with_invalid_readme_but_valid_header_is_supported(tmp_path):
    archive_path = tmp_path / "bad-readme.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("plugin.php", "<?php\n/*\nPlugin Name: Zip Plugin\n*/\n")
        archive.writestr("readme.txt", "This is not a WordPress readme header.\n")

    result = Scanner(str(archive_path)).scan()

    assert result.errors == []
    assert result.plugin_name == "Zip Plugin"


def test_multiline_malware_signature_is_detected(temp_plugin_dir):
    with open(os.path.join(temp_plugin_dir, "multiline.php"), "w", encoding="utf-8") as file_obj:
        file_obj.write(
            "<?php\n"
            "eval(\n"
            "    base64_decode('PD9waHAgZWNobyAnaGknOw==')\n"
            ");\n"
        )

    result = Scanner(temp_plugin_dir).scan()

    assert any(finding.pattern.id == "PHP-RCE-002" for finding in result.findings)


def test_offline_heuristic_detects_obfuscated_backdoor(temp_plugin_dir):
    long_blob = "QUFB" * 80
    with open(os.path.join(temp_plugin_dir, "heuristic.php"), "w", encoding="utf-8") as file_obj:
        file_obj.write(
            "<?php\n"
            "$runner = 'assert';\n"
            f"@$runner(base64_decode('{long_blob}'));\n"
            "$x = chr(101).chr(118).chr(97).chr(108).chr(40).chr(41).chr(59);\n"
        )

    result = Scanner(temp_plugin_dir, deep_scan=True).scan()

    assert any(finding.pattern.id == "PHP-MALWARE-HEUR-001" for finding in result.findings)


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
    with open(os.path.join(temp_plugin_dir, "image.png"), "wb") as file_obj:
        file_obj.write(b"\x89PNG\r\n\x1a\n")

    open(os.path.join(temp_plugin_dir, "empty.php"), "w", encoding="utf-8").close()

    with open(os.path.join(temp_plugin_dir, "large.php"), "w", encoding="utf-8") as file_obj:
        file_obj.write("<?php\n" + "A" * 4096)

    result = Scanner(temp_plugin_dir, max_file_size_kb=1).scan()

    assert result.errors == []
    assert "image.png" in result.files_skipped
    assert "empty.php" in result.files_skipped
    assert "large.php" in result.files_skipped

