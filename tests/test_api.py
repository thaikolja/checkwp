"""API regression tests for upload and AI activation flows."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

import checkwp.api as api_module


def _zip_plugin(plugin_dir: str, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in Path(plugin_dir).rglob("*"):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(plugin_dir))


def test_api_index_and_health():
    client = TestClient(api_module.app)

    index_response = client.get("/")
    assert index_response.status_code == 200
    assert index_response.json()["service"] == "checkwp-api"

    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json()["status"] == "ok"


def test_api_scan_returns_json(vulnerable_plugin, tmp_path):
    archive_path = tmp_path / "plugin.zip"
    _zip_plugin(vulnerable_plugin, archive_path)

    client = TestClient(api_module.app)
    with archive_path.open("rb") as file_obj:
        response = client.post("/scan?format=json", files={"file": (archive_path.name, file_obj, "application/zip")})

    assert response.status_code == 200
    data = response.json()
    assert data["plugin_name"] == "Test Plugin"
    assert data["summary"]["total"] >= 3


def test_api_uses_ai_when_api_key_present(vulnerable_plugin, tmp_path, monkeypatch):
    archive_path = tmp_path / "plugin.zip"
    _zip_plugin(vulnerable_plugin, archive_path)
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

    monkeypatch.setattr(api_module, "AIAnalyzer", FakeAnalyzer)
    client = TestClient(api_module.app)
    with archive_path.open("rb") as file_obj:
        response = client.post(
            "/scan?format=json&ai_key=token-xyz&ai_endpoint=https://api.deepseek.com/v1&ai_model=deepseek-chat",
            files={"file": (archive_path.name, file_obj, "application/zip")},
        )

    assert response.status_code == 200
    assert response.json()["ai_enabled"] is True
    assert calls == {
        "api_key":     "token-xyz",
        "model":       "deepseek-chat",
        "base_url":    "https://api.deepseek.com/v1",
        "temperature": 0.1,
        "checked":     True,
        "analyzed":    True,
    }
