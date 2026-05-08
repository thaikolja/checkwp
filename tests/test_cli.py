"""CLI regression tests for user-facing argument handling and report generation."""

import pytest

from checkwp.cli import main


def test_cli_help():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_cli_no_args():
    # Calling without args should return 1 (our custom behavior)
    assert main([]) == 1


def test_cli_invalid_path():
    assert main(["/non/existent/path"]) == 1


def test_cli_rejects_conflicting_language_filters(vulnerable_plugin):
    assert main([vulnerable_plugin, "--php-only", "--js-only", "--no-banner"]) == 1


def test_cli_basic_scan(vulnerable_plugin, tmp_path):
    output = tmp_path / "report.html"
    # Run scan on vulnerable plugin
    ret = main([vulnerable_plugin, "-o", str(output), "--no-open", "--no-banner"])
    assert ret == 0
    assert output.exists()
