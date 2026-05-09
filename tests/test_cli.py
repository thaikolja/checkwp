"""CLI regression tests for user-facing argument handling and report generation."""

import pytest

from checkwp.ai import analyzer as analyzer_module
from checkwp.cli import main, resolve_ai_endpoint


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


def test_cli_rejects_removed_ai_flag(vulnerable_plugin):
    with pytest.raises(SystemExit):
        main([vulnerable_plugin, "--ai", "--no-banner"])


def test_resolve_ai_endpoint_defaults_and_urls():
    assert resolve_ai_endpoint(None) == "https://api.openai.com/v1"
    assert resolve_ai_endpoint("https://example.com/v1/") == "https://example.com/v1"
    with pytest.raises(ValueError):
        resolve_ai_endpoint("deepseek")


def test_cli_basic_scan(vulnerable_plugin, tmp_path):
    output = tmp_path / "report.html"
    # Run scan on vulnerable plugin
    ret = main([vulnerable_plugin, "-o", str(output), "--no-open", "--no-banner"])
    assert ret == 0
    assert output.exists()
    assert output.with_suffix(".md").exists()
    assert output.with_suffix(".pdf").exists()


def test_cli_api_key_enables_ai(vulnerable_plugin, tmp_path, monkeypatch):
    output = tmp_path / "report.html"
    calls: dict[str, object] = {}

    class FakeAnalyzer:
        def __init__(self, api_key: str, model: str, base_url: str, temperature: float):
            calls["api_key"] = api_key
            calls["model"] = model
            calls["base_url"] = base_url
            calls["temperature"] = temperature

        def check_connection(self):
            calls["checked"] = True

        def analyze_findings(self, result):
            calls["analyzed"] = True
            result.ai_enabled = True
            return result

    monkeypatch.setattr(analyzer_module, "AIAnalyzer", FakeAnalyzer)

    ret = main(
        [
            vulnerable_plugin,
            "-o",
            str(output),
            "--no-open",
            "--no-banner",
            "--ai-key",
            "token-123",
            "--ai-endpoint",
            "https://api.deepseek.com/v1",
            "--ai-model",
            "deepseek-chat",
        ]
    )

    assert ret == 0
    assert calls == {
        "api_key":     "token-123",
        "model":       "deepseek-chat",
        "base_url":    "https://api.deepseek.com/v1",
        "temperature": 0.1,
        "checked":     True,
        "analyzed":    True,
    }


def test_cli_default_report_goes_to_temp_folder(vulnerable_plugin, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    ret = main([vulnerable_plugin, "--no-open", "--no-banner"])

    assert ret == 0
    expected = tmp_path / "temp" / "test-plugin-security-report.html"
    assert expected.exists()
    assert expected.with_suffix(".md").exists()
    assert expected.with_suffix(".pdf").exists()

